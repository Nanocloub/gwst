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

	h.bufferPool = utils.NewBufferPool(utils.UDPBufferSize)

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

// decryptUDPData 解密 UDP 数据的辅助方法
// 性能关键：直接解密到目标 buffer，零额外分配和复制
func (h *Handler) decryptUDPData(buffer *[]byte, encryptedData []byte) (int, error) {
	if h.cryptoManager == nil {
		// 无加密时直接复制
		return copy(*buffer, encryptedData), nil
	}
	
	// 直接解密到目标 buffer，避免中间缓冲区
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

	// Set keep-alive timeouts to ensure the connection doesn't hang
	ws.SetReadDeadline(time.Now().Add(90 * time.Second))

	// Ping goroutine to keep connection alive
	go func() {
		ticker := time.NewTicker(time.Second * 30)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// 尝试获取锁，使用非阻塞方式避免死锁和goroutine泄漏
				lockCtx, lockCancel := context.WithTimeout(context.Background(), 5*time.Second)
				
				locked := make(chan bool, 1)
				
				go func() {
					writeMu.Lock()
					select {
					case locked <- true:
						// 成功通知
					case <-lockCtx.Done():
						// 超时了，释放锁
						writeMu.Unlock()
					}
				}()

				select {
				case <-locked:
					// 成功获取锁，发送 ping
					ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
					err := pingCodec.Send(ws, nil)
					if err == nil {
						ws.SetReadDeadline(time.Now().Add(90 * time.Second))
						ws.SetWriteDeadline(time.Time{})
						writeMu.Unlock()
						lockCancel()
						continue
					}
					writeMu.Unlock()
					lockCancel()

					h.log.Errorf("Failed to send ping: %v", err)
					_ = ws.Close()
					return

				case <-lockCtx.Done():
					// 超时，跳过本次 ping（goroutine 会自动释放锁）
					lockCancel()
					h.log.Warn("Failed to acquire write lock for ping within 5s, skipping this ping cycle")
					continue
				}
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
		n, err = h.decryptUDPData(buffer, (*buffer)[:n])
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

		// 解密首个消息（如果启用加密）
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
	
	// 使用 sync.Once 确保连接只关闭一次
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	defer closeConn() // 异常安全：确保 panic 时也能关闭连接

	// 使用 CryptoConn 处理 WebSocket 的消息边界、加密和解密
	// LockedConn 确保写入线程安全（与 ping goroutine 共享 writeMu）
	// CryptoConn.Read 有独立的 readMu 保护内部 readBuf，读写可以并发
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: ws, Mu: writeMu}, h.cryptoManager, false)

	// Send response for the first UDP packet (already read during dial)
	_, err = tunnelConn.Write((*readBuffer)[:rn])

	if err != nil {
		utils.PutBuffer(h.bufferPool, readBuffer)
		h.log.Errorf("Failed to write response to WebSocket: %v", err)
		return
	}

	var wg sync.WaitGroup
	
	// 启动读取 goroutine：从 Tunnel 读取并写入 Target
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn() // 使用 sync.Once 包装的关闭函数
		defer utils.PutBuffer(h.bufferPool, readBuffer)

		// UDP: Read from Tunnel -> Decrypt -> Write to Target
		// 复用 tunnelConn 作为 reader，WebSocket 读取不需要锁保护
		if _, err := utils.CopyBufferWithWriteTimeout(conn, tunnelConn, *readBuffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data from Tunnel to Target: %v", err)
		}
	}()

	// UDP: Read from Target -> Encrypt -> Write to Tunnel
	writeBuffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, writeBuffer)
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(utils.DeadlineWriter), conn, *writeBuffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data from Target to Tunnel: %v", err)
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
	
	// 使用 sync.Once 确保连接只关闭一次
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { conn.Close() }) }
	defer closeConn() // 异常安全：确保 panic 时也能关闭连接

	var wg sync.WaitGroup

	// 创建单个 CryptoConn 实例用于双向传输
	// - 写入：LockedConn 提供锁保护（与 ping goroutine 共享 writeMu）
	// - 读取：CryptoConn 内部 readMu 保护 readBuf，与写入互不干扰
	// - 并发安全：底层 WebSocket 读写可以在不同 goroutine 中安全进行
	tunnelConn := utils.NewCryptoConn(&utils.LockedConn{Conn: ws, Mu: writeMu}, h.cryptoManager, false)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn() // 使用 sync.Once 包装的关闭函数
		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// Direction: Tunnel(ws) -> Target(conn)
		// WebSocket 模式下，每次 Read 都会获取完整消息，不会有帧交错问题
		if _, err := utils.CopyBufferWithWriteTimeout(conn, tunnelConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	// Direction: Target(conn) -> Tunnel(ws)
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(utils.DeadlineWriter), conn, *buffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to Tunnel: %v", err)
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

	// 对于 UDP 协议，使用特殊处理
	if protocol == "udp" {
		return h.handleRawUDP(conn, target, fallbackAddrs)
	}

	// Directly duplicate data
	targetConn, err := dial(context.Background(), protocol, target, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to target: %v", err)
		return err
	}
	
	// 使用 sync.Once 确保连接只关闭一次
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { targetConn.Close() }) }
	defer closeConn() // 异常安全：确保 panic 时也能关闭连接

	var wg sync.WaitGroup

	// Stream 模式：创建单个 CryptoConn 实例处理双向加密通信
	// - 帧协议：[Len(2)][EncryptedPayload] 确保边界清晰
	// - 并发安全：CryptoConn 内部 readMu 保护读缓冲，读写可并发
	tunnelConn := utils.NewCryptoConn(conn, h.cryptoManager, true)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn() // 使用 sync.Once 包装的关闭函数
		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		// Direction: Tunnel(conn) -> Target(targetConn)
		if _, err := utils.CopyBufferWithWriteTimeout(targetConn, tunnelConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data to Target: %v", err)
		}
	}()

	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	// Direction: Target(targetConn) -> Tunnel(conn)
	if _, err := utils.CopyBufferWithWriteTimeout(tunnelConn.(deadlineWriter), targetConn, *buffer, utils.DefaultWriteTimeout); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data to Tunnel: %v", err)
	}

	wg.Wait()
	return nil
}

// handleRawUDP 处理原始连接上的 UDP 流量（用于 TCP/QUIC 传输）
// UDP over stream: 使用简单的长度前缀帧格式
func (h *Handler) handleRawUDP(conn net.Conn, addr string, fallbackAddrs []string) error {
	// 使用统一的 dial 函数处理 fallback，保持逻辑一致性
	targetConn, err := dial(context.Background(), "udp", addr, fallbackAddrs)
	if err != nil {
		h.log.Errorf("Failed to connect to UDP target: %v", err)
		return err
	}
	
	// 使用 sync.Once 确保连接只关闭一次
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { targetConn.Close() }) }
	defer closeConn() // 异常安全：确保 panic 时也能关闭连接

	var wg sync.WaitGroup

	// Stream 模式的 UDP：使用 CryptoConn 统一处理加密和帧封装
	// - 即使无加密（cryptoManager=nil），也需要帧协议保证 UDP 包边界
	// - 并发安全：内部 readMu 保护，读写可在不同 goroutine 并发执行
	tunnelConn := utils.NewCryptoConn(conn, h.cryptoManager, true)

	// 从客户端读取，写入目标（客户端 -> 服务端 -> 目标）
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer closeConn() // 使用 sync.Once 包装的关闭函数

		buffer := utils.GetBuffer(h.bufferPool)
		defer utils.PutBuffer(h.bufferPool, buffer)

		if _, err := io.CopyBuffer(targetConn, tunnelConn, *buffer); err != nil &&
			!errors.Is(err, net.ErrClosed) {
			h.log.Infof("Failed to copy data from Tunnel to UDP Target: %v", err)
		}
	}()

	// 从目标读取，写入客户端（目标 -> 服务端 -> 客户端）
	buffer := utils.GetBuffer(h.bufferPool)
	defer utils.PutBuffer(h.bufferPool, buffer)

	if _, err := io.CopyBuffer(tunnelConn, targetConn, *buffer); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		h.log.Infof("Failed to copy data from UDP Target to Tunnel: %v", err)
	}

	wg.Wait()
	return nil
}

func isStreamConn(conn net.Conn) bool {
	return utils.IsStreamConn(conn)
}

