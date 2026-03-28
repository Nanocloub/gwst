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
	DefaultUDPDialReadTimeout     = time.Second * 2
	DefaultUDPEarlyDataHeaderName = "Sec-WebSocket-Protocol"
	DefaultUDPMaxEarlyDataSize    = 4 * 1024
	// DefaultUDPIdleTimeout 是 UDP 后端连接的读取空闲超时。
	// 若后端在此时间内无响应（如静默崩溃、无 ICMP），读操作返回超时错误，
	// 触发连接清理，避免 goroutine/内存泄露。
	DefaultUDPIdleTimeout = 2 * time.Minute
)

// NamedTarget 命名的目标地址配置
type NamedTarget struct {
	// 主地址
	Addr string

	// 回退地址列表
	FallbackAddrs []string
}

type GetTargetFunc func(req *http.Request) (string, []string, error)

type Logger = utils.Logger
type CryptoManager = utils.CryptoManager
type deadlineWriter = utils.DeadlineWriter

type Handler struct {
	log                    Logger
	getTargetFunc          GetTargetFunc
	allowedTargets         map[string][]string
	namedTargets           map[string]NamedTarget
	wsServer               *websocket.Server
	bufferPool             *sync.Pool // 65KB pool，供 UDP 路径使用
	tcpCopyPool            *sync.Pool // 16KB pool，供 TCP 双向复制使用
	closeChan              chan struct{}
	cryptoManager          CryptoManager
	key                    string
	udpEarlyDataHeaderName string
	defaultTargetAddr      string
	fallbackAddrs          []string
	connectionsWg          sync.WaitGroup
	bufferSize             int
	udpDialReadTimeout     time.Duration
	udpIdleTimeout         time.Duration
	closeOnce              sync.Once
	disableTCPProtocol     bool
	disableUDPProtocol     bool
	loadBalance            bool
}

type HandlerOption func(*Handler)

// udpTargetConn 为 UDP 后端连接的 Read 加入滚动空闲超时。
// 每次 Read 调用前重置读 deadline，确保后端静默崩溃（无 ICMP）时
// 读取在 idleTimeout 内退出，触发上层连接清理，避免 goroutine 泄露。
type udpTargetConn struct {
	net.Conn
	idleTimeout time.Duration
}

func (u *udpTargetConn) Read(b []byte) (int, error) {
	if err := u.Conn.SetReadDeadline(time.Now().Add(u.idleTimeout)); err != nil {
		return 0, err
	}
	return u.Conn.Read(b)
}

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

func WithHandlerUDPIdleTimeout(timeout time.Duration) HandlerOption {
	return func(h *Handler) {
		h.udpIdleTimeout = timeout
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

	h.bufferPool = utils.NewBufferPool(utils.UDPBufferSize)
	h.tcpCopyPool = utils.NewBufferPool(utils.DefaultBufferSize)

	if h.udpDialReadTimeout == 0 {
		h.udpDialReadTimeout = DefaultUDPDialReadTimeout
	}

	if h.udpIdleTimeout == 0 {
		h.udpIdleTimeout = DefaultUDPIdleTimeout
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

// decryptUDPData 解密 UDP 数据的辅助方法
// 性能关键：直接解密到目标 buffer，零额外分配和复制
func (h *Handler) decryptUDPData(buffer *[]byte, encryptedData []byte) (int, error) {
	if h.cryptoManager == nil {
		return copy(*buffer, encryptedData), nil
	}

	decrypted, err := h.cryptoManager.DecryptTo(*buffer, encryptedData)
	if err != nil {
		return 0, err
	}

	return len(decrypted), nil
}

func (h *Handler) handle(ws *websocket.Conn, network, addr string, fallbackAddrs []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex

	ws.SetReadDeadline(time.Now().Add(90 * time.Second))

	go func() {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// TryLock: 若写锁正被数据拷贝 goroutine 持有，跳过本次 ping，避免阻塞。
				if !writeMu.TryLock() {
					continue
				}
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				err := pingCodec.Send(ws, nil)
				ws.SetWriteDeadline(time.Time{})
				writeMu.Unlock()
				if err != nil {
					h.log.Errorf("Failed to send ping: %v", err)
					_ = ws.Close()
					return
				}
				ws.SetReadDeadline(time.Now().Add(90 * time.Second))
			case <-h.closeChan:
				h.log.Infof("Closing connection due to shutdown")
				_ = ws.Close()
				return
			case <-ctx.Done():
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
		decodedLen := base64.StdEncoding.DecodedLen(len(base64Str))
		if decodedLen > len(*buffer) {
			h.log.Errorf("X-0RTT header too large: %d bytes (buffer: %d)", decodedLen, len(*buffer))
			return
		}
		n, err = base64.StdEncoding.Decode(*buffer, utils.StringToBytes(base64Str))
		if err != nil {
			h.log.Errorf("Failed to decode X-0RTT header: %v", err)
			return
		}

		// 解密 early data（如果启用加密）
		// 注意：必须先将密文复制到独立切片，避免 DecryptTo 的 dst(*buffer) 和
		// src((*buffer)[:n]) 指向同一内存，原地解密在部分 AEAD 实现中不安全。
		ciphertext := make([]byte, n)
		copy(ciphertext, (*buffer)[:n])
		n, err = h.decryptUDPData(buffer, ciphertext)
		if err != nil {
			h.log.Errorf("Failed to decrypt X-0RTT header: %v", err)
			return
		}
	} else {
		err = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			h.log.Errorf("Failed to set read deadline: %v", err)
			return
		}

		var message []byte
		err = websocket.Message.Receive(ws, &message)
		if err != nil {
			h.log.Errorf("Failed to read from tunnel connection: %v", err)
			return
		}

		n, err = h.decryptUDPData(buffer, message)
		if err != nil {
			h.log.Errorf("Failed to decrypt first packet: %v", err)
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
		utils.PutBuffer(h.bufferPool, readBuffer)
		h.log.Errorf("Failed to connect to UDP target: %v", err)
		return
	}

	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	defer closeConn()

	// LockedConn 保证写入线程安全（与 ping goroutine 共享 writeMu）
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: ws, Mu: writeMu}, h.cryptoManager, false)

	// Send response for the first UDP packet (already read during dial)
	_, err = tunnelConn.Write((*readBuffer)[:rn])
	if err != nil {
		utils.PutBuffer(h.bufferPool, readBuffer)
		h.log.Errorf("Failed to write response to WebSocket: %v", err)
		return
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn()
		defer utils.PutBuffer(h.bufferPool, readBuffer)

		// Tunnel -> Target
		if _, err := utils.CopyBufferWithWriteTimeout(conn, tunnelConn, *readBuffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data from Tunnel to Target: %v", err)
		}
	}()

	// Target -> Tunnel（udpTargetConn 为每次 Read 重置读 deadline，防止后端静默崩溃导致永久阻塞）
	writeBuffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, writeBuffer)
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(utils.DeadlineWriter), &udpTargetConn{Conn: conn, idleTimeout: h.udpIdleTimeout}, *writeBuffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data from Target to Tunnel: %v", err)
	}

	closeConn()
	ws.Close()

	wg.Wait()
}

func (h *Handler) handleNetwork(ws *websocket.Conn, network, addr string, fallbackAddrs []string, writeMu *sync.Mutex) {
	conn, err := dial(ws.Request().Context(), network, addr, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return
	}

	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	defer closeConn()

	var wg sync.WaitGroup

	// LockedConn 保证写入线程安全（与 ping goroutine 共享 writeMu）
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: ws, Mu: writeMu}, h.cryptoManager, false)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn()
		buffer := utils.GetBuffer(h.tcpCopyPool)
		defer utils.PutBuffer(h.tcpCopyPool, buffer)

		// Tunnel -> Target
		if _, err := utils.CopyBufferWithWriteTimeout(conn, tunnelConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.tcpCopyPool)
	defer utils.PutBuffer(h.tcpCopyPool, buffer)

	// Target -> Tunnel
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(utils.DeadlineWriter), conn, *buffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to Tunnel: %v", err)
	}

	closeConn()
	ws.Close()

	wg.Wait()
}

func dial(ctx context.Context, network, addr string, fallbackAddrs []string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		setTCPKeepAlive(conn)
		return conn, nil
	}

	if len(fallbackAddrs) == 0 {
		return nil, err
	}

	errs := []error{err}
	for _, addr := range fallbackAddrs {
		conn, batchErr := d.DialContext(ctx, "tcp", addr)
		if batchErr == nil {
			setTCPKeepAlive(conn)
			return conn, nil
		}

		errs = append(errs, batchErr)
	}

	return nil, errors.Join(errs...)
}

// setTCPKeepAlive 为 TCP 连接启用 keepalive，确保后端进程崩溃或异常退出时，
// OS 能在 ~90s 内检测到死连接并返回错误，避免 goroutine 永久阻塞。
func setTCPKeepAlive(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
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

		// 回收失败时分配的 buffer，防止内存泄漏
		if buffer != nil {
			utils.PutBuffer(h.bufferPool, buffer)
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
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, new(net.Error)) && err.(net.Error).Timeout()) {
			// Ignore read timeout on the first packet, as some UDP services may not respond immediately.
			// This allows the tunnel to be established even for silent backends.
			h.log.Infof("UDP target %s is silent on dial, proceeding anyway", addr)
			return buffer, 0, conn, nil
		}
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

	if protocol == "udp" {
		return h.handleRawUDP(conn, target, fallbackAddrs)
	}

	targetConn, err := dial(context.Background(), protocol, target, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return err
	}

	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { targetConn.Close() }) }
	defer closeConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex

	conn.SetReadDeadline(time.Now().Add(utils.StreamReadTimeout))
	go h.streamKeepalive(ctx, conn, &writeMu)

	var wg sync.WaitGroup

	// LockedConn 保证写入线程安全（与 keepalive goroutine 共享 writeMu）
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: conn, Mu: &writeMu}, h.cryptoManager, true)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn()
		buffer := utils.GetBuffer(h.tcpCopyPool)
		defer utils.PutBuffer(h.tcpCopyPool, buffer)

		// Tunnel -> Target
		if _, err := utils.CopyBufferWithWriteTimeout(targetConn, tunnelConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.tcpCopyPool)
	defer utils.PutBuffer(h.tcpCopyPool, buffer)

	// Target -> Tunnel
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(deadlineWriter), targetConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to Tunnel: %v", err)
	}

	closeConn()
	conn.Close()

	wg.Wait()
	return nil
}

// streamKeepalive 为 TCP/QUIC 流式隧道连接提供应用层心跳。
// 功能等同于 WebSocket 模式的 ping goroutine：
//   - 每 30s 发送零长度帧 [0x00, 0x00] 作为心跳
//   - 刷新读超时（90s），若隧道断开，心跳写入失败 → 读超时未刷新 → 读操作超时退出
//   - CryptoConn.Read() 的 stream 模式自动跳过 ln==0 的帧
func (h *Handler) streamKeepalive(ctx context.Context, conn net.Conn, writeMu *sync.Mutex) {
	ticker := time.NewTicker(utils.StreamKeepaliveInterval)
	defer ticker.Stop()

	keepaliveFrame := []byte{0, 0}

	for {
		select {
		case <-ticker.C:
			// TryLock: 若数据拷贝正在写入，跳过本次心跳，避免阻塞。
			if !writeMu.TryLock() {
				continue
			}
			conn.SetWriteDeadline(time.Now().Add(utils.StreamKeepaliveWriteTimeout))
			_, err := conn.Write(keepaliveFrame)
			conn.SetWriteDeadline(time.Time{})
			writeMu.Unlock()
			if err != nil {
				h.log.Infof("Stream keepalive write failed: %v", err)
				conn.Close()
				return
			}
			conn.SetReadDeadline(time.Now().Add(utils.StreamReadTimeout))
		case <-h.closeChan:
			h.log.Infof("Closing stream connection due to shutdown")
			conn.Close()
			return
		case <-ctx.Done():
			return
		}
	}
}

// handleRawUDP 处理原始连接上的 UDP 流量（用于 TCP/QUIC 传输）
// UDP over stream: 使用简单的长度前缀帧格式
func (h *Handler) handleRawUDP(conn net.Conn, addr string, fallbackAddrs []string) error {
	targetConn, err := dial(context.Background(), "udp", addr, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to UDP target: %v", err)
		return err
	}

	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { targetConn.Close() }) }
	defer closeConn()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writeMu sync.Mutex

	conn.SetReadDeadline(time.Now().Add(utils.StreamReadTimeout))
	go h.streamKeepalive(ctx, conn, &writeMu)

	var wg sync.WaitGroup

	// LockedConn 保证写入线程安全（与 keepalive goroutine 共享 writeMu）
	// isStream=true: 即使无加密也需要帧协议保证 UDP 包边界
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: conn, Mu: &writeMu}, h.cryptoManager, true)

	// Tunnel -> Target
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn()

		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		if _, err := io.CopyBuffer(targetConn, tunnelConn, *buffer); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data from Tunnel to UDP Target: %v", err)
		}
	}()

	// Target -> Tunnel（必须用写超时：若客户端保持连接但停止读取，Write 会永久阻塞）
	// udpTargetConn 为每次 Read 重置读 deadline，防止后端静默崩溃导致永久阻塞。
	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(deadlineWriter), &udpTargetConn{Conn: targetConn, idleTimeout: h.udpIdleTimeout}, *buffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data from UDP Target to Tunnel: %v", err)
	}

	closeConn()
	conn.Close()

	wg.Wait()
	return nil
}
