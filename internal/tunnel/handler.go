package tunnel

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/zijiren233/gwst/internal/utils"
)

const (
	DefaultUDPDialReadTimeout     = time.Second / 2
	DefaultUDPEarlyDataHeaderName = "Sec-WebSocket-Protocol"
	DefaultUDPMaxEarlyDataSize    = 4 * 1024
)

// NamedTarget 命名的目标地址配置
type NamedTarget struct {
	// 主地址
	Addr string

	// 回退地址列表
	FallbackAddrs []string
}

type GetTargetFunc func(req *http.Request) (string, []string, error)

// 导出接口别名以支持向后兼容
type Logger = utils.Logger
type CryptoManager = utils.CryptoManager
type deadlineWriter = utils.DeadlineWriter

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

func NewHandler(opts ...HandlerOption) *Handler {
	h := &Handler{
		closeChan: make(chan struct{}),
	}

	for _, opt := range opts {
		opt(h)
	}

	if h.bufferSize == 0 {
		h.bufferSize = utils.DefaultBufferSize
	}

	h.bufferPool = utils.NewBufferPool(h.bufferSize)

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

	h.log = utils.NewSafeLoggerOrNull(h.log)

	return h
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

type lockedWriter struct {
	w  deadlineWriter
	mu *sync.Mutex
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, err := w.w.Write(p)
	w.mu.Unlock()
	return n, err
}

func (w *lockedWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	err := w.w.SetWriteDeadline(t)
	w.mu.Unlock()
	return err
}

func (h *Handler) handle(ws *websocket.Conn, network, addr string, fallbackAddrs []string) {
	exit := make(chan struct{})
	defer close(exit)

	var writeMu sync.Mutex

	// Set keep-alive timeouts to ensure the connection doesn't hang
	ws.SetReadDeadline(time.Now().Add(90 * time.Second))

	// Ping goroutine to keep connection alive
	go func() {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				writeMu.Lock()
				// Set write deadline to prevent hanging on slow/blocked connections
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := pingCodec.Send(ws, nil)
				if err == nil {
					// Update read deadline after successful send
					ws.SetReadDeadline(time.Now().Add(90 * time.Second))
					// Clear write deadline
					ws.SetWriteDeadline(time.Time{})
					writeMu.Unlock()
					continue
				}
				writeMu.Unlock()

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
		h.handleUDP(ws, addr, fallbackAddrs, &writeMu)
		return
	}

	h.handleNetwork(ws, network, addr, fallbackAddrs, &writeMu)
}

func (h *Handler) handleUDP(ws *websocket.Conn, addr string, fallbackAddrs []string, writeMu *sync.Mutex) {
	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	var (
		n   int
		err error
	)

	base64Str := ws.Request().Header.Get(h.udpEarlyDataHeaderName)
	if base64Str != "" {
		if base64.StdEncoding.DecodedLen(len(base64Str)) > len(*buffer) {
			h.log.Errorf("X-0RTT header too large")
			return
		}
		n, err = base64.StdEncoding.Decode(*buffer, utils.StringToBytes(base64Str))
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
			h.log.Errorf("Failed to read from tunnel connection: %v", err)
			return
		}

		if h.cryptoManager != nil {
			// Acquire a temporary buffer for decryption to avoid allocation
			dstBuf := utils.GetBuffer(h.bufferPool)
			decrypted, err := h.cryptoManager.DecryptTo(*dstBuf, *buffer)
			if err != nil {
				utils.PutBuffer(h.bufferPool, dstBuf)
				h.log.Errorf("Failed to decrypt X-0RTT/First packet: %v", err)
				return
			}
			// Copy decrypted data back to buffer
			n = copy(*buffer, decrypted)
			utils.PutBuffer(h.bufferPool, dstBuf)
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
		utils.PutBuffer(h.bufferPool, readBuffer)
		h.log.Errorf("Failed to connect to UDP target: %v", err)
		return
	}
	defer conn.Close()

	writeMu.Lock()
	var writeErr error
	if h.cryptoManager != nil {
		dstBuf := utils.GetBuffer(h.bufferPool)
		encrypted, err := h.cryptoManager.EncryptTo(*dstBuf, (*readBuffer)[:rn])
		if err != nil {
			utils.PutBuffer(h.bufferPool, dstBuf)
			writeMu.Unlock()
			utils.PutBuffer(h.bufferPool, readBuffer)
			h.log.Errorf("Failed to encrypt response: %v", err)
			return
		}
		_, writeErr = ws.Write(encrypted)
		utils.PutBuffer(h.bufferPool, dstBuf)
	} else {
		_, writeErr = ws.Write((*readBuffer)[:rn])
	}

	if writeErr != nil {
		writeMu.Unlock()
		utils.PutBuffer(h.bufferPool, readBuffer)
		h.log.Errorf("Failed to write to WebSocket: %v", writeErr)
		return
	}
	writeMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer conn.Close()
		defer utils.PutBuffer(h.bufferPool, readBuffer)

		// UDP: Read from WS(Tunnel) -> Decrypt -> Write to Target
		// Note: copyWithDecryption expects the source to be length-prefixed stream.
		// BUT WebSocket messages are already framed.
		// If h.cryptoManager is used, we need packet-based decryption if it's WebSocket.
		// Wait, copyWithDecryption is designed for Stream (TCP).
		// For UDP over WebSocket, we just loop Read/Write packets.

		if h.cryptoManager != nil {
			// Custom loop for Encrypted Message based UDP
			buf := *readBuffer
			dstBuf := utils.GetBuffer(h.bufferPool)
			defer utils.PutBuffer(h.bufferPool, dstBuf)

			for {
				n, err := ws.Read(buf)
				if err != nil {
					if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
						h.log.Infof("Failed to read from Tunnel: %v", err)
					}
					return
				}

				decrypted, err := h.cryptoManager.DecryptTo(*dstBuf, buf[:n])
				if err != nil {
					h.log.Warnf("Failed to decrypt UDP packet: %v", err)
					return
				}

				if _, err := conn.Write(decrypted); err != nil {
					h.log.Infof("Failed to write to Target: %v", err)
					return
				}
			}
		} else {
			if _, err := utils.CopyBufferWithWriteTimeout(conn, ws, *readBuffer, utils.DefaultWriteTimeout); err != nil &&
				!errors.Is(err, net.ErrClosed) {
				h.log.Infof("Failed to copy data to Target: %v", err)
			}
		}
	}()

	lockedWs := &lockedWriter{w: ws, mu: writeMu}

	if h.cryptoManager != nil {
		// Custom loop for Target(UDP) -> Encrypt -> WS(Tunnel)
		buf := *buffer
		dstBuf := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, dstBuf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					h.log.Infof("Failed to read from Target: %v", err)
				}
				return
			}

			// We must encrypt before protecting with lock?
			// Ideally yes, but we need to write to lockedWs.
			encrypted, err := h.cryptoManager.EncryptTo(*dstBuf, buf[:n])
			if err != nil {
				h.log.Warnf("Failed to encrypt UDP packet: %v", err)
				return
			}

			if _, err := lockedWs.Write(encrypted); err != nil {
				h.log.Infof("Failed to write to Tunnel: %v", err)
				return
			}
		}
	} else {
		if _, err := utils.CopyBufferWithWriteTimeout(lockedWs, conn, *buffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to WebSocket: %v", err)
		}
	}

	// Wait for the copy goroutine to finish
	wg.Wait()
}

func (h *Handler) handleNetwork(ws *websocket.Conn, network, addr string, fallbackAddrs []string, writeMu *sync.Mutex) {
	conn, err := dial(ws.Request().Context(), network, addr, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer conn.Close()
		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// Direction: Tunnel(ws) -> Target(conn)
		// We read Encrypted stream from Tunnel, Decrypt, Write Plain to Target.
		if _, err := h.copyWithDecryption(conn, ws, *buffer); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	lockedWs := &lockedWriter{w: ws, mu: writeMu}

	// Direction: Target(conn) -> Tunnel(ws)
	// We read Plain from Target, Encrypt, Write Encrypted stream to Tunnel.
	if _, err := h.copyWithEncryption(lockedWs, conn, *buffer); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to WebSocket: %v", err)
	}

	// Wait for the copy goroutine to finish
	wg.Wait()
}

func dial(ctx context.Context, network, addr string, fallbackAddrs []string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}

	if len(fallbackAddrs) == 0 {
		return nil, err
	}

	errs := []error{err}
	for _, addr := range fallbackAddrs {
		conn, batchErr := d.DialContext(ctx, "tcp", addr)
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

	buffer := utils.GetBuffer(h.bufferPool)

	err = conn.SetReadDeadline(time.Now().Add(h.udpDialReadTimeout))
	if err != nil {
		utils.PutBuffer(h.bufferPool, buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	rn, err := conn.Read(*buffer)
	if err != nil {
		utils.PutBuffer(h.bufferPool, buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		utils.PutBuffer(h.bufferPool, buffer)
		conn.Close()
		return nil, 0, nil, err
	}

	return buffer, rn, conn, nil
}

// copyWithEncryption copies data from src to dst, encrypting if crypto manager is available
func (h *Handler) copyWithEncryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	return utils.CopyWithEncryption(dst, src, buf, h.cryptoManager, utils.DefaultWriteTimeout)
}

// copyWithDecryption copies data from src to dst, decrypting if crypto manager is available
func (h *Handler) copyWithDecryption(dst deadlineWriter, src io.Reader, buf []byte) (written int64, err error) {
	return utils.CopyWithDecryption(dst, src, buf, h.cryptoManager, utils.DefaultWriteTimeout)
}

func (h *Handler) Close() {
	h.closeOnce.Do(func() {
		close(h.closeChan)
	})
}

func (h *Handler) Wait() {
	h.connectionsWg.Wait()
}

// GetDefaultTarget 返回默认目标地址
func (h *Handler) GetDefaultTarget() string {
	return h.defaultTargetAddr
}

// GetFallbackAddrs 返回回退地址列表
func (h *Handler) GetFallbackAddrs() []string {
	return h.fallbackAddrs
}

// HandleRawConnection 处理原始连接（用于 TCP/QUIC 传输）
func (h *Handler) HandleRawConnection(conn net.Conn, protocol, target string, fallbackAddrs []string) error {
	h.connectionsWg.Add(1)
	defer h.connectionsWg.Done()

	h.log.Infof(
		"Received %s connection:\n\tAddr: %v\n\tTarget: %s\n\tFallback: %v\n\tProtocol: %s",
		protocol,
		conn.RemoteAddr(),
		target,
		fallbackAddrs,
		protocol,
	)

	if h.loadBalance {
		target, fallbackAddrs = BalanceTargets(target, fallbackAddrs)
	}

	// 对于 UDP 协议，使用特殊处理
	if protocol == "udp" {
		return h.handleRawUDP(conn, target, fallbackAddrs)
	}

	// 直接复制数据
	targetConn, err := dial(context.Background(), protocol, target, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return err
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer targetConn.Close()
		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// Direction: Tunnel(conn) -> Target(targetConn)
		// Tunnel sends [Len][Encrypted]. We Read, Decrypt, Write Raw to Target.
		if _, err := h.copyWithDecryption(targetConn, conn, *buffer); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	// Direction: Target(targetConn) -> Tunnel(conn)
	// Target sends Raw. We Read, Encrypt, Frame [Len][Encrypted], Write to Tunnel.
	if _, err := h.copyWithEncryption(conn, targetConn, *buffer); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to Tunnel: %v", err)
	}

	wg.Wait()
	return nil
}

// handleRawUDP 处理原始连接上的 UDP 流量（用于 TCP/QUIC 传输）
// UDP over stream: 使用简单的长度前缀帧格式
func (h *Handler) handleRawUDP(conn net.Conn, addr string, fallbackAddrs []string) error {
	// 连接到 UDP 目标
	targetConn, err := net.Dial("udp", addr)
	if err != nil {
		if len(fallbackAddrs) == 0 {
			h.log.Errorf("Failed to connect to UDP target: %v", err)
			return err
		}

		// 尝试回退地址
		var errs []error
		errs = append(errs, err)
		for _, fallbackAddr := range fallbackAddrs {
			targetConn, err = net.Dial("udp", fallbackAddr)
			if err == nil {
				h.log.Infof("Connected to fallback UDP target: %s", fallbackAddr)
				break
			}
			errs = append(errs, err)
		}

		if targetConn == nil {
			h.log.Errorf("Failed to connect to UDP target: %v", errors.Join(errs...))
			return errors.Join(errs...)
		}
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	// 从客户端读取，写入目标（客户端 -> 服务端 -> 目标）
	go func() {
		defer wg.Done()
		defer targetConn.Close()

		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// 预分配 lenBuf，避免在循环中重复分配
		var lenBuf [2]byte

		for {
			// 读取帧长度（2字节）
			if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					h.log.Infof("Failed to read UDP frame length from client: %v", err)
				}
				return
			}

			frameLen := int(lenBuf[0])<<8 | int(lenBuf[1])
			if frameLen == 0 {
				h.log.Warnf("Received zero-length UDP frame from client, ignoring")
				continue
			}
			if frameLen > len(*buffer) {
				h.log.Errorf("UDP frame too large: %d bytes (buffer: %d)", frameLen, len(*buffer))
				return
			}

			// 读取帧数据
			if _, err := io.ReadFull(conn, (*buffer)[:frameLen]); err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					h.log.Infof("Failed to read UDP frame data from client: %v", err)
				}
				return
			}

			dataToWrite := (*buffer)[:frameLen]
			if h.cryptoManager != nil {
				// Use a temporary buffer for decryption
				dstBuf := utils.GetBuffer(h.bufferPool)
				decrypted, err := h.cryptoManager.DecryptTo(*dstBuf, dataToWrite)
				if err != nil {
					utils.PutBuffer(h.bufferPool, dstBuf)
					h.log.Warnf("Failed to decrypt UDP frame: %v", err)
					return
				}
				// Write decrypted data to target
				_, err = targetConn.Write(decrypted)
				utils.PutBuffer(h.bufferPool, dstBuf)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						h.log.Infof("Failed to write to UDP target: %v", err)
					}
					return
				}
			} else {
				// 写入目标
				if _, err := targetConn.Write(dataToWrite); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						h.log.Infof("Failed to write to UDP target: %v", err)
					}
					return
				}
			}
		}
	}()

	// 从目标读取，写入客户端（目标 -> 服务端 -> 客户端）
	go func() {
		defer wg.Done()
		defer conn.Close()
		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// 预分配帧缓冲区，最大 65535 + 2 字节
		frameBuffer := make([]byte, 2+len(*buffer))

		for {
			// 读取 UDP 数据包
			n, err := targetConn.Read(*buffer)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					h.log.Infof("Failed to read from UDP target: %v", err)
				}
				return
			}

			if n == 0 {
				continue
			}

			dataLen := n
			var dataToSend []byte

			if h.cryptoManager != nil {
				// Calculate required size for encrypted data
				// Overhead is usually fixed but let's rely on EncryptTo logic or just ensure buffer is big enough
				// EncryptTo needs dst to be large enough.
				// We can reuse frameBuffer for encryption destination if we are careful.
				// frameBuffer structure: [Len(2)][EncryptedData...]

				// Max overhead for AEGIS-128L is 32 bytes.
				// We need to ensure frameBuffer is large enough.
				maxEncLen := dataLen + 32 // 32 is cryptoOverhead constant in copy.go but not exported here. 32 is safe.
				if len(frameBuffer) < 2+maxEncLen {
					frameBuffer = make([]byte, 2+maxEncLen)
				}

				encrypted, err := h.cryptoManager.EncryptTo(frameBuffer[2:], (*buffer)[:n])
				if err != nil {
					h.log.Warnf("Failed to encrypt UDP frame: %v", err)
					return
				}
				dataToSend = encrypted
				dataLen = len(encrypted)

				// fill length
				frameBuffer[0] = byte(dataLen >> 8)
				frameBuffer[1] = byte(dataLen & 0xff)

				// write frame
				if _, err := conn.Write(frameBuffer[:2+dataLen]); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						h.log.Infof("Failed to write to client: %v", err)
					}
					return
				}
			} else {
				dataToSend = (*buffer)[:n]

				if dataLen > 65535 {
					h.log.Errorf("Packet too large: %d", dataLen)
					continue
				}

				// 封装成帧：长度 + 数据，使用单次 Write 减少系统调用
				// Ensure frameBuffer is large enough
				if len(frameBuffer) < 2+dataLen {
					frameBuffer = make([]byte, 2+dataLen)
				}

				frameBuffer[0] = byte(dataLen >> 8)
				frameBuffer[1] = byte(dataLen & 0xff)
				copy(frameBuffer[2:], dataToSend)

				if _, err := conn.Write(frameBuffer[:2+dataLen]); err != nil {
					if !errors.Is(err, net.ErrClosed) {
						h.log.Infof("Failed to write to client: %v", err)
					}
					return
				}
			}
		}
	}()

	wg.Wait()
	return nil
}
