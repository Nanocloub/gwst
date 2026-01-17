package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/zijiren233/gwst/internal/transport"
)

const (
	DefaultUDPDialReadTimeout     = time.Second / 2
	DefaultUDPEarlyDataHeaderName = "Sec-WebSocket-Protocol"
	DefaultUDPMaxEarlyDataSize    = 4 * 1024
)

// NamedTarget is an alias for transport.NamedTarget to unify the type definition
type NamedTarget = transport.NamedTarget

type GetTargetFunc func(req *http.Request) (string, []string, error)

type Logger interface {
	Infof(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
	Error(...interface{})
}

type CryptoManager interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type deadlineWriter interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

type Handler struct {
	log                    Logger
	getTargetFunc          GetTargetFunc
	allowedTargets         map[string][]string
	namedTargets           map[string]NamedTarget
	wsServer               *websocket.Server
	bufferPool             *sync.Pool
	closeChan              chan struct{}
	cryptoManager          CryptoManager
	key                    string
	udpEarlyDataHeaderName string
	defaultTargetAddr      string
	fallbackAddrs          []string
	connectionsWg          sync.WaitGroup
	bufferSize             int
	udpDialReadTimeout     time.Duration
	closeOnce              sync.Once
	disableTCPProtocol     bool
	disableUDPProtocol     bool
	loadBalance            bool
}

type HandlerOption func(*Handler)

func WithHandlerLogger(logger Logger) HandlerOption {
	return func(h *Handler) {
		h.log = logger
	}
}

func WithHandlerGetTargetFunc(getTargetFunc GetTargetFunc) HandlerOption {
	return func(h *Handler) {
		h.getTargetFunc = getTargetFunc
	}
}

func WithHandlerDefaultTargetAddr(targetAddr string) HandlerOption {
	return func(h *Handler) {
		h.defaultTargetAddr = targetAddr
	}
}

func WithHandlerFallbackAddrs(fallbackAddrs []string) HandlerOption {
	return func(h *Handler) {
		h.fallbackAddrs = fallbackAddrs
	}
}

func WithHandlerAllowedTargets(allowedTargets map[string][]string) HandlerOption {
	return func(h *Handler) {
		if len(allowedTargets) > 0 {
			h.allowedTargets = allowedTargets
		}
	}
}

func WithHandlerNamedTargets(namedTargets map[string]NamedTarget) HandlerOption {
	return func(h *Handler) {
		h.namedTargets = namedTargets
	}
}

func WithHandlerBufferSize(size int) HandlerOption {
	return func(h *Handler) {
		h.bufferSize = size
	}
}

func WithHandlerLoadBalance(loadBalance bool) HandlerOption {
	return func(h *Handler) {
		h.loadBalance = loadBalance
	}
}

func WithHandlerUDPDialReadTimeout(timeout time.Duration) HandlerOption {
	return func(h *Handler) {
		h.udpDialReadTimeout = timeout
	}
}

func WithHandlerDisableTCPProtocol(disable bool) HandlerOption {
	return func(h *Handler) {
		h.disableTCPProtocol = disable
	}
}

func WithHandlerDisableUDPProtocol(disable bool) HandlerOption {
	return func(h *Handler) {
		h.disableUDPProtocol = disable
	}
}

func WithHandlerUDPEarlyDataHeaderName(name string) HandlerOption {
	return func(h *Handler) {
		h.udpEarlyDataHeaderName = name
	}
}

func WithHandlerKey(key string) HandlerOption {
	return func(h *Handler) {
		h.key = key
	}
}

func WithHandlerCryptoManager(cm CryptoManager) HandlerOption {
	return func(h *Handler) {
		h.cryptoManager = cm
	}
}

func checkOrigin(config *websocket.Config, req *http.Request) (err error) {
	config.Origin, err = websocket.Origin(config, req)
	if err == nil && config.Origin == nil {
		return errors.New("null origin")
	}

	return err
}

func newCheckOrigin(key string) func(config *websocket.Config, req *http.Request) (err error) {
	if key == "" {
		return checkOrigin
	}

	return func(config *websocket.Config, req *http.Request) (err error) {
		err = checkOrigin(config, req)
		if err != nil {
			return err
		}

		if key != req.Header.Get("X-Key") {
			return errors.New("invalid key")
		}

		return nil
	}
}

func newSafeLogger(logger Logger) Logger {
	if logger != nil {
		return logger
	}
	return &nullLogger{}
}

type nullLogger struct{}

func (n *nullLogger) Infof(string, ...interface{})  {}
func (n *nullLogger) Errorf(string, ...interface{}) {}
func (n *nullLogger) Warnf(string, ...interface{})  {}
func (n *nullLogger) Error(...interface{})          {}

func newBufferPool(size int) *sync.Pool {
	const defaultBufferSize = 16 * 1024
	if size == defaultBufferSize || size <= 0 {
		return &sync.Pool{
			New: func() any {
				buffer := make([]byte, defaultBufferSize)
				return &buffer
			},
		}
	}

	return &sync.Pool{
		New: func() any {
			buffer := make([]byte, size)
			return &buffer
		},
	}
}

func NewHandler(opts ...HandlerOption) *Handler {
	h := &Handler{
		closeChan: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(h)
	}

	const defaultBufferSize = 16 * 1024
	if h.bufferSize == 0 {
		h.bufferSize = defaultBufferSize
	}

	h.bufferPool = newBufferPool(h.bufferSize)

	if h.udpDialReadTimeout == 0 {
		h.udpDialReadTimeout = DefaultUDPDialReadTimeout
	}

	if h.udpEarlyDataHeaderName == "" {
		h.udpEarlyDataHeaderName = DefaultUDPEarlyDataHeaderName
	}

	h.wsServer = &websocket.Server{
		Handler:   h.handleWebSocket,
		Handshake: newCheckOrigin(h.key),
	}

	if h.getTargetFunc == nil {
		h.getTargetFunc = h.getTarget
	}

	h.log = newSafeLogger(h.log)

	return h
}

func (h *Handler) getBuffer() *[]byte {
	return h.bufferPool.Get().(*[]byte)
}

func (h *Handler) putBuffer(buffer *[]byte) {
	if buffer != nil {
		*buffer = (*buffer)[:cap(*buffer)]
		h.bufferPool.Put(buffer)
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.connectionsWg.Add(1)
	defer h.connectionsWg.Done()

	h.wsServer.ServeHTTP(w, req)
}

func (h *Handler) handleWebSocket(ws *websocket.Conn) {
	defer ws.Close()

	ws.PayloadType = websocket.BinaryFrame

	protocol := getProtocol(ws.Request().Header.Get("X-Protocol"))
	if h.disableTCPProtocol && protocol == "tcp" {
		h.log.Error("TCP protocol is disabled")
		return
	}

	if h.disableUDPProtocol && protocol == "udp" {
		h.log.Error("UDP protocol is disabled")
		return
	}

	target, fallbackAddrs, err := h.getTargetFunc(ws.Request())
	if err != nil {
		h.log.Errorf("Error getting target: %v", err)
		return
	}

	if target == "" && len(fallbackAddrs) == 0 {
		h.log.Error("No target found")
		return
	}

	if target == "" && len(fallbackAddrs) > 0 {
		target = fallbackAddrs[0]
		fallbackAddrs = fallbackAddrs[1:]
	}

	h.log.Infof(
		"Received WebSocket connection:\n\tAddr: %v\n\tHost: %s\n\tOrigin: %s\n\tTarget: %s\n\tFallback: %v\n\tProtocol: %s",
		ws.Request().RemoteAddr,
		ws.Request().Host,
		ws.RemoteAddr(),
		target,
		fallbackAddrs,
		protocol,
	)

	if h.loadBalance {
		target, fallbackAddrs = BalanceTargets(target, fallbackAddrs)
	}

	h.handle(ws, protocol, target, fallbackAddrs)
}

func getProtocol(requestProtocol string) string {
	switch requestProtocol {
	case "udp":
		return "udp"
	default:
		return "tcp"
	}
}

func (h *Handler) getTarget(req *http.Request) (string, []string, error) {
	requestTarget := req.Header.Get("X-Target")

	namedTarget := req.Header.Get("X-Named-Target")
	if namedTarget != "" {
		if target, ok := h.namedTargets[namedTarget]; ok {
			return target.Addr, target.FallbackAddrs, nil
		}
	}

	if requestTarget == "" || requestTarget == h.defaultTargetAddr || len(h.allowedTargets) == 0 {
		return h.defaultTargetAddr, h.fallbackAddrs, nil
	}

	if v, ok := h.allowedTargets[requestTarget]; ok {
		return requestTarget, v, nil
	}

	return "", nil, fmt.Errorf("target %s not allowed", requestTarget)
}

func BalanceTargets(target string, fallbackAddrs []string) (string, []string) {
	if len(fallbackAddrs) == 0 {
		return target, fallbackAddrs
	}

	allAddrs := make([]string, 0, len(fallbackAddrs)+1)
	if target != "" {
		allAddrs = append(allAddrs, target)
	}

	for _, addr := range fallbackAddrs {
		if addr != "" {
			allAddrs = append(allAddrs, addr)
		}
	}

	rand.Shuffle(len(allAddrs), func(i, j int) {
		allAddrs[i], allAddrs[j] = allAddrs[j], allAddrs[i]
	})

	return allAddrs[0], allAddrs[1:]
}

var pingCodec = websocket.Codec{
	Marshal: func(_ any) ([]byte, byte, error) {
		return nil, websocket.PingFrame, nil
	},
}

func (h *Handler) handle(ws *websocket.Conn, network, addr string, fallbackAddrs []string) {
	exit := make(chan struct{})
	defer close(exit)

	go func() {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				err := pingCodec.Send(ws, nil)
				if err == nil {
					continue
				}

				h.log.Errorf("Failed to send ping: %v", err)

				_ = ws.Close()

				return
			case <-h.closeChan:
			h.log.Infof("Closing connection due to shutdown")

				_ = ws.Close()
				return
			case <-exit:
				return
			}
		}
	}()

	if network == "udp" {
		h.handleUDP(ws, addr, fallbackAddrs)
		return
	}

	h.handleNetwork(ws, network, addr, fallbackAddrs)
}

func (h *Handler) handleUDP(ws *websocket.Conn, addr string, fallbackAddrs []string) {
	buffer := h.getBuffer()
	defer h.putBuffer(buffer)

	var (
		n   int
		err error
	)

	base64Str := ws.Request().Header.Get(h.udpEarlyDataHeaderName)
	if base64Str != "" {
		n, err = base64.StdEncoding.Decode(*buffer, stringToBytes(base64Str))
		if err != nil {
			h.log.Errorf("Failed to decode X-0RTT header: %v", err)
			return
		}
	} else {
		err = ws.SetReadDeadline(time.Now().Add(time.Second))
		if err != nil {
			h.log.Errorf("Failed to set read deadline: %v", err)
			return
		}

		n, err = ws.Read(*buffer)
		if err != nil {
			h.log.Errorf("Failed to read from WebSocket: %v", err)
			return
		}

		err = ws.SetReadDeadline(time.Time{})
		if err != nil {
			h.log.Errorf("Failed to set read deadline: %v", err)
			return
		}
	}

	readBuffer, rn, conn, err := h.dialUDP(
		ws.Request().Context(),
		(*buffer)[:n],
		addr,
		fallbackAddrs,
	)
	if err != nil {
		h.putBuffer(readBuffer)
		h.log.Errorf("Failed to connect to UDP target: %v", err)
		return
	}
	defer conn.Close()

	if _, err = ws.Write((*readBuffer)[:rn]); err != nil {
		h.putBuffer(readBuffer)
		h.log.Errorf("Failed to write to WebSocket: %v", err)
		return
	}

	go func() {
		defer h.putBuffer(readBuffer)

		if _, err := copyBufferWithWriteTimeout(conn, ws, *readBuffer, 15*time.Second); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	if _, err := copyBufferWithWriteTimeout(ws, conn, *buffer, 15*time.Second); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to WebSocket: %v", err)
	}
}

func (h *Handler) handleNetwork(ws *websocket.Conn, network, addr string, fallbackAddrs []string) {
	conn, err := dial(ws.Request().Context(), network, addr, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return
	}
	defer conn.Close()

	go func() {
		buffer := h.getBuffer()
		defer h.putBuffer(buffer)

		if _, err := h.copyWithEncryption(conn, ws, *buffer); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := h.getBuffer()
	defer h.putBuffer(buffer)

	if _, err := h.copyWithDecryption(ws, conn, *buffer); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to WebSocket: %v", err)
	}
}

func dial(_ context.Context, network, addr string, fallbackAddrs []string) (net.Conn, error) {
	conn, err := net.Dial(network, addr)
	if err == nil {
		return conn, nil
	}

	if len(fallbackAddrs) == 0 {
		return nil, err
	}

	errs := []error{err}
	for _, addr := range fallbackAddrs {
		conn, batchErr := net.Dial("tcp", addr)
		if batchErr == nil {
			return conn, nil
		}

		errs = append(errs, batchErr)
	}

	return nil, errors.Join(errs...)
}

func (h *Handler) dialUDP(
	ctx context.Context,
	earlyData []byte,
	addr string,
	fallbackAddrs []string,
) (*[]byte, int, net.Conn, error) {
	buffer, rn, conn, err := h.dialAndCheckUDP(ctx, earlyData, addr)
	if err == nil {
		return buffer, rn, conn, nil
	}

	if len(fallbackAddrs) == 0 {
		return nil, 0, nil, err
	}

	errs := []error{err}
	for _, addr := range fallbackAddrs {
		buffer, rn, conn, batchErr := h.dialAndCheckUDP(ctx, earlyData, addr)
		if batchErr == nil {
			h.log.Infof(
				"Warning: Target '%s' is unreachable: [%v], using fallback '%s'",
				addr,
				err,
				conn.RemoteAddr().String(),
			)

			return buffer, rn, conn, nil
		}

		errs = append(errs, batchErr)
	}

	return nil, 0, nil, errors.Join(errs...)
}

func (h *Handler) dialAndCheckUDP(
	_ context.Context,
	earlyData []byte,
	addr string,
) (*[]byte, int, net.Conn, error) {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, 0, nil, err
	}

	n, err := conn.Write(earlyData)
	if err != nil {
		conn.Close()
		return nil, 0, nil, err
	}

	if len(earlyData) != n {
		conn.Close()
		return nil, 0, nil, errors.New("invalid write result")
	}

	buffer := h.getBuffer()

	err = conn.SetReadDeadline(time.Now().Add(h.udpDialReadTimeout))
	if err != nil {
		h.putBuffer(buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	rn, err := conn.Read(*buffer)
	if err != nil {
		h.putBuffer(buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		h.putBuffer(buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	return buffer, rn, conn, nil
}

func copyBufferWithWriteTimeout(
	dst deadlineWriter,
	src io.Reader,
	buf []byte,
	timeout time.Duration,
) (written int64, err error) {
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			err = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				break
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0

				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nw)

			if ew != nil {
				err = ew
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

// copyWithEncryption copies data from src to dst, encrypting if crypto manager is available
func (h *Handler) copyWithEncryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	if h.cryptoManager == nil {
		return copyBufferWithWriteTimeout(dst, src, buf, 15*time.Second)
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Encrypt the data
			encrypted, encErr := h.cryptoManager.Encrypt(buf[:nr])
			if encErr != nil {
				err = encErr
				break
			}

			err = dst.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err != nil {
				break
			}

			nw, ew := dst.Write(encrypted)
			if nw < 0 || len(encrypted) < nw {
				nw = 0

				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nr)

			if ew != nil {
				err = ew
				break
			}

			if len(encrypted) != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

// copyWithDecryption copies data from src to dst, decrypting if crypto manager is available
func (h *Handler) copyWithDecryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	if h.cryptoManager == nil {
		return copyBufferWithWriteTimeout(dst, src, buf, 15*time.Second)
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// Decrypt the data
			decrypted, decErr := h.cryptoManager.Decrypt(buf[:nr])
			if decErr != nil {
				err = decErr
				break
			}

			err = dst.SetWriteDeadline(time.Now().Add(15 * time.Second))
			if err != nil {
				break
			}

			nw, ew := dst.Write(decrypted)
			if nw < 0 || len(decrypted) < nw {
				nw = 0

				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nw)

			if ew != nil {
				err = ew
				break
			}

			if len(decrypted) != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		close(h.closeChan)
	})
}

func (h *Handler) Wait() {
	h.connectionsWg.Wait()
}

func stringToBytes(s string) []byte {
	return []byte(s)
}
