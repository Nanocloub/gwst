package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/congestion"

	"github.com/zijiren233/gwst/internal/congestion/bbr"
)

// QUICServerTransport QUIC 服务端传输实现
type QUICServerTransport struct {
	listener     *quic.Listener
	listenErr    error
	onListened   chan struct{}
	shutdowned   chan struct{}
	config       TransportServerConfig
	connectionWg sync.WaitGroup
	onListenOnce sync.Once
	shutdownOnce sync.Once
	// ctx/cancel: 用于在 Close() 时取消所有 Accept/AcceptStream，
	// 使 handleConnection goroutine 能快速退出（避免固定 5 秒等待）。
	ctx    context.Context
	cancel context.CancelFunc
}

// defaultQuicInitialPacketSize is the default initial UDP packet size:
// 1500 (Ethernet) - 20 (IPv4) - 8 (UDP) - 20 (QUIC overhead) = 1452.
// This skips the quic-go default 1280-byte warmup phase on standard Ethernet paths.
// quic-go's SetCongestionControl does NOT propagate the current datagram size
// to the replacement CC, so BBR must be initialized with the same value as
// quic.Config.InitialPacketSize to avoid pacing budget mismatches.
const (
	defaultQuicInitialPacketSize uint16 = 1452
	minQuicInitialPacketSize     uint16 = 1200 // QUIC spec minimum (RFC 9000 §14)
)

// resolveInitialPacketSize returns the configured value clamped to [1200, 1452],
// or the default (1452) when configured is 0.
// Clamping is essential: quic-go silently clamps values below 1200 to 1200
// inside populateConfig, so if we let an out-of-range value reach both
// quic.Config.InitialPacketSize and BBR's initialMaxDatagramSize, they would
// diverge and cause pacing budget mismatches.
func resolveInitialPacketSize(configured uint16) uint16 {
	if configured == 0 {
		return defaultQuicInitialPacketSize
	}
	if configured < minQuicInitialPacketSize {
		return minQuicInitialPacketSize
	}
	if configured > defaultQuicInitialPacketSize {
		return defaultQuicInitialPacketSize
	}
	return configured
}

// NewQUICServerTransport 创建 QUIC 服务端传输
func NewQUICServerTransport(cfg TransportServerConfig) (*QUICServerTransport, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("listen_addr is required")
	}

	if cfg.Handler == nil {
		return nil, errors.New("handler is required")
	}

	if !cfg.TLS {
		return nil, errors.New("QUIC requires TLS to be enabled")
	}

	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, errors.New("cert_file and key_file are required for QUIC")
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	return &QUICServerTransport{
		onListened: make(chan struct{}),
		shutdowned: make(chan struct{}),
		config:     cfg,
	}, nil
}

// Serve 启动 QUIC 服务
func (qst *QUICServerTransport) Serve() error {
	// 创建生命周期 context；Close() 调用 cancel() 通知所有阻塞的 Accept/AcceptStream
	ctx, cancel := context.WithCancel(context.Background())
	qst.ctx = ctx
	qst.cancel = cancel
	defer cancel() // 始终释放 context 资源；cancel 多次调用是幂等的
	defer qst.onListenOnce.Do(func() {
		close(qst.onListened)
	})
	defer qst.shutdownOnce.Do(func() {
		close(qst.shutdowned)
	})

	// Load TLS certificate
	cert, err := tls.LoadX509KeyPair(qst.config.CertFile, qst.config.KeyFile)
	if err != nil {
		qst.listenErr = err
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
		MinVersion:   tls.VersionTLS13,
	}

	// Create QUIC listener
	// MaxIdleTimeout=0 → quic-go 内置默认 30s；两端协商取较小值
	initialPacketSize := resolveInitialPacketSize(qst.config.QUICInitialPacketSize)

	listener, err := quic.ListenAddr(qst.config.ListenAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout:                 qst.config.QUICMaxIdleTimeout,
		KeepAlivePeriod:                30 * time.Second,
		InitialPacketSize:              initialPacketSize,
		InitialStreamReceiveWindow:     qst.config.QUICInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         qst.config.QUICMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: qst.config.QUICInitialConnReceiveWindow,
		MaxConnectionReceiveWindow:     qst.config.QUICMaxConnReceiveWindow,
		MaxIncomingStreams:             qst.config.QUICMaxIncomingStreams,
		DisablePathMTUDiscovery:        qst.config.QUICDisablePathMTUDiscovery,
	})
	if err != nil {
		qst.listenErr = err
		return err
	}

	qst.listener = listener

	qst.onListenOnce.Do(func() {
		close(qst.onListened)
	})

	qst.config.Logger.Infof("QUIC server listening on %s", qst.config.ListenAddr)

	// Accept connections
	for {
		conn, err := listener.Accept(qst.ctx)
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) || qst.ctx.Err() != nil {
				return nil
			}
			qst.config.Logger.Errorf("Failed to accept QUIC connection: %v", err)
			continue
		}

		setBBR(conn, initialPacketSize) // reuse the same value given to quic.Config
		qst.connectionWg.Add(1)
		go qst.handleConnection(conn)
	}
}

// handleConnection 处理单个 QUIC 连接
func (qst *QUICServerTransport) handleConnection(conn *quic.Conn) {
	// defer 顺序（LIFO）：
	//   3. connectionWg.Done()      — 最后执行，通知 Close() 本连接已完全清理
	//   2. streamWg.Wait()          — 等待所有流 goroutine 退出
	//   1. conn.CloseWithError(...) — 最先执行，强制终止所有流 I/O，使 goroutine 快速退出
	defer qst.connectionWg.Done()
	var streamWg sync.WaitGroup
	defer streamWg.Wait()
	defer conn.CloseWithError(0, "connection closed")

	for {
		stream, err := conn.AcceptStream(qst.ctx)
		if err != nil {
			return
		}

		streamWg.Add(1)
		go func(s *quic.Stream) {
			defer streamWg.Done()
			defer s.Close()
			if err := qst.config.Handler(&quicStreamWrapper{Stream: s, conn: conn}); err != nil {
				qst.config.Logger.Infof("Stream handler error: %v", err)
			}
		}(stream)
	}
}

// WaitListen 等待服务启动
func (qst *QUICServerTransport) WaitListen() error {
	<-qst.onListened
	return qst.listenErr
}

// WaitShutdown 等待服务关闭
func (qst *QUICServerTransport) WaitShutdown() <-chan struct{} {
	return qst.shutdowned
}

// Close 关闭 QUIC 服务
func (qst *QUICServerTransport) Close() error {
	qst.shutdownOnce.Do(func() {
		// 先取消 context：使所有阻塞在 Accept/AcceptStream 的 goroutine 立即返回
		if qst.cancel != nil {
			qst.cancel()
		}

		if qst.listener != nil {
			qst.listener.Close()
		}

		// 等待所有连接 goroutine 退出（现在有 ctx 取消，不会长时间阻塞）
		done := make(chan struct{})
		go func() {
			qst.connectionWg.Wait()
			close(done)
		}()

		// 使用 Timer 而不是 time.After，避免泄漏
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()

		select {
		case <-done:
		case <-timer.C:
		}

		close(qst.shutdowned)
	})

	return nil
}

// QUICClientTransport QUIC 客户端传输实现。
//
// 持有一个持久 QUIC 连接，每次 Dial 在该连接上开新流（stream multiplexing），
// 避免每次建立隧道都触发 TLS 1.3 完整握手（高延迟场景代价显著）。
// 当底层连接断开时，下次 Dial 自动重建。
type QUICClientTransport struct {
	config      TransportClientConfig
	mu          sync.Mutex   // 保护 conn 和 closed 字段；持有时间短
	reconnectMu sync.Mutex   // 序列化重连操作（持有期间可能阻塞 dialNewConn）
	conn        *quic.Conn   // 持久复用的 QUIC 连接；nil 表示尚未建立或已失效
	tlsCfg      *tls.Config  // 预构建，不可变，避免每次 Dial 重复分配
	quicCfg     *quic.Config // 预构建，不可变
	closed      bool
}

// NewQUICClientTransport 创建 QUIC 客户端传输，预构建 TLS/QUIC 配置以避免运行时重复分配。
func NewQUICClientTransport(cfg TransportClientConfig) (*QUICClientTransport, error) {
	if cfg.RemoteAddr == "" {
		return nil, errors.New("remote_addr is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	tlsCfg := &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.Insecure,
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
	}
	switch {
	case cfg.CACertPool != nil:
		tlsCfg.RootCAs = cfg.CACertPool
	case cfg.CACertFile != "":
		pool, err := LoadCACertPool(cfg.CACertFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}

	initialPacketSize := resolveInitialPacketSize(cfg.QUICInitialPacketSize)
	quicCfg := &quic.Config{
		MaxIdleTimeout:                 cfg.QUICMaxIdleTimeout, // 0 → quic-go 内置默认 30s
		KeepAlivePeriod:                30 * time.Second,
		InitialPacketSize:              initialPacketSize,
		InitialStreamReceiveWindow:     cfg.QUICInitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         cfg.QUICMaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: cfg.QUICInitialConnReceiveWindow,
		MaxConnectionReceiveWindow:     cfg.QUICMaxConnReceiveWindow,
		DisablePathMTUDiscovery:        cfg.QUICDisablePathMTUDiscovery,
	}

	return &QUICClientTransport{
		config:  cfg,
		tlsCfg:  tlsCfg,
		quicCfg: quicCfg,
	}, nil
}

// isAlive 在持有外部锁的情况下安全检查 transport 是否可用。
// 调用者必须持有 mu。
func (qct *QUICClientTransport) isAlive() bool {
	return !qct.closed && (qct.conn == nil || qct.conn.Context().Err() == nil)
}

// setBBR sets BBR congestion control on a QUIC connection.
// initialPacketSize must match quic.Config.InitialPacketSize used when the
// connection was dialed/accepted, because quic-go's SetCongestionControl does
// not propagate the current datagram size to the newly installed CC.
func setBBR(conn *quic.Conn, initialPacketSize uint16) {
	conn.SetCongestionControl(bbr.NewBbrSender(
		bbr.DefaultClock{},
		congestion.ByteCount(initialPacketSize),
		bbr.ProfileStandard,
	))
}

// dialNewConn 建立全新的 QUIC 连接。只读取不可变字段（config/tlsCfg/quicCfg），无需持锁。
func (qct *QUICClientTransport) dialNewConn(ctx context.Context) (*quic.Conn, error) {
	pktSize := qct.quicCfg.InitialPacketSize
	if qct.config.ListenConfig != nil {
		pconn, err := qct.config.ListenConfig.ListenPacket(ctx, "udp", "")
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket: %w", err)
		}
		tr := &quic.Transport{Conn: pconn}
		addr, err := net.ResolveUDPAddr("udp", qct.config.RemoteAddr)
		if err != nil {
			pconn.Close()
			return nil, fmt.Errorf("failed to resolve remote addr: %w", err)
		}
		conn, err := tr.Dial(ctx, addr, qct.tlsCfg, qct.quicCfg)
		if err != nil {
			pconn.Close()
			return nil, err
		}
		setBBR(conn, pktSize)
		return conn, nil
	}
	conn, err := quic.DialAddr(ctx, qct.config.RemoteAddr, qct.tlsCfg, qct.quicCfg)
	if err != nil {
		return nil, err
	}
	setBBR(conn, pktSize)
	return conn, nil
}

// Dial 在持久 QUIC 连接上开一个新流。首次调用建立连接；后续调用复用连接，
// 无需重新握手（stream multiplexing）。连接断开时自动重建。
//
// 并发设计：
//   - mu 仅用于原子读取/清零 conn 字段（持有时间极短，微秒级）
//   - OpenStreamSync 始终在 reconnectMu 之外调用，允许多个 goroutine 同时在同一
//     QUIC 连接上并发开流，互不阻塞（quic.Connection 的方法是 goroutine-safe）
//   - reconnectMu 仅在 dialNewConn 期间持有，序列化重连操作，确保最多一个
//     goroutine 执行握手；连接建立后立即释放，OpenStreamSync 并发进行
func (qct *QUICClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	// 快速路径：在 mu 保护下获取当前连接引用，然后立即释放 mu。
	// OpenStreamSync 在锁外调用，允许并发流开启。
	qct.mu.Lock()
	if qct.closed {
		qct.mu.Unlock()
		return nil, net.ErrClosed
	}
	conn := qct.conn
	if conn != nil && conn.Context().Err() != nil {
		qct.conn = nil
		conn = nil
	}
	qct.mu.Unlock()

	if conn != nil {
		stream, err := conn.OpenStreamSync(ctx) // 无锁调用，并发安全
		if err == nil {
			return &quicStreamConn{stream: stream, conn: conn}, nil
		}
		// 连接已失效，清零缓存
		qct.mu.Lock()
		if qct.conn == conn {
			qct.conn = nil
		}
		qct.mu.Unlock()
	}

	// 慢路径：需要重建连接；用 reconnectMu 序列化 dialNewConn，防止多个 goroutine
	// 同时握手。注意：不使用 defer，在连接就绪后立即手动释放，确保 OpenStreamSync
	// 始终在 reconnectMu 之外并发执行。
	qct.reconnectMu.Lock()

	// 二次检查：持有 reconnectMu 期间可能已有其他 goroutine 完成了重连
	qct.mu.Lock()
	if qct.closed {
		qct.mu.Unlock()
		qct.reconnectMu.Unlock()
		return nil, net.ErrClosed
	}
	conn = qct.conn
	if conn != nil && conn.Context().Err() != nil {
		qct.conn = nil
		conn = nil
	}
	qct.mu.Unlock()

	if conn == nil {
		// 建立全新 QUIC 连接（耗时操作，在 reconnectMu 保护下只执行一次）
		newConn, err := qct.dialNewConn(ctx)
		if err != nil {
			qct.reconnectMu.Unlock()
			return nil, err
		}
		qct.mu.Lock()
		if qct.closed {
			qct.mu.Unlock()
			qct.reconnectMu.Unlock()
			newConn.CloseWithError(0, "transport closed")
			return nil, net.ErrClosed
		}
		qct.conn = newConn
		qct.mu.Unlock()
		conn = newConn
	}

	// 连接已就绪（来自二次检查或新建），立即释放 reconnectMu。
	// 后续 OpenStreamSync 并发执行，不持有任何锁。
	qct.reconnectMu.Unlock()

	stream, err := conn.OpenStreamSync(ctx) // 无锁调用，并发安全
	if err != nil {
		// 流开启失败（连接已死），清空缓存；调用方重试时将重新握手
		qct.mu.Lock()
		if qct.conn == conn {
			qct.conn = nil
		}
		qct.mu.Unlock()
		return nil, err
	}
	return &quicStreamConn{stream: stream, conn: conn}, nil
}

// Close 关闭 QUIC 连接
func (qct *QUICClientTransport) Close() error {
	qct.mu.Lock()
	if qct.closed {
		qct.mu.Unlock()
		return nil
	}
	qct.closed = true
	conn := qct.conn
	qct.conn = nil
	qct.mu.Unlock() // 先释放 mu，再调网络 I/O（CloseWithError 发送 CONNECTION_CLOSE 帧）

	if conn != nil {
		return conn.CloseWithError(0, "transport closed")
	}
	return nil
}

// quicStreamWrapper wraps a QUIC stream to implement net.Conn
type quicStreamWrapper struct {
	Stream *quic.Stream
	conn   *quic.Conn
}

func (q *quicStreamWrapper) Read(b []byte) (int, error) {
	return q.Stream.Read(b)
}

func (q *quicStreamWrapper) Write(b []byte) (int, error) {
	return q.Stream.Write(b)
}

func (q *quicStreamWrapper) Close() error {
	// CancelRead 向对端发送 STOP_SENDING，立即终止流的接收方向，
	// 防止在 handler 出错返回时流的读侧长期半开（resource leak）。
	// 在成功路径上数据已全部读完，调用无副作用（幂等）。
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

func (q *quicStreamWrapper) LocalAddr() net.Addr {
	return q.conn.LocalAddr()
}

func (q *quicStreamWrapper) RemoteAddr() net.Addr {
	return q.conn.RemoteAddr()
}

func (q *quicStreamWrapper) SetDeadline(t time.Time) error {
	return q.Stream.SetDeadline(t)
}

func (q *quicStreamWrapper) SetReadDeadline(t time.Time) error {
	return q.Stream.SetReadDeadline(t)
}

func (q *quicStreamWrapper) SetWriteDeadline(t time.Time) error {
	return q.Stream.SetWriteDeadline(t)
}

// quicStreamConn wraps a QUIC stream to implement net.Conn for client
type quicStreamConn struct {
	stream *quic.Stream
	conn   *quic.Conn
}

func (qc *quicStreamConn) Read(b []byte) (int, error) {
	return qc.stream.Read(b)
}

func (qc *quicStreamConn) Write(b []byte) (int, error) {
	return qc.stream.Write(b)
}

func (qc *quicStreamConn) LocalAddr() net.Addr {
	return qc.conn.LocalAddr()
}

func (qc *quicStreamConn) RemoteAddr() net.Addr {
	return qc.conn.RemoteAddr()
}

func (qc *quicStreamConn) Close() error {
	// 只关闭流；QUIC 连接由 QUICClientTransport 管理并复用于后续流。
	// 流关闭会发送 STREAM FIN，对端 AcceptStream 侧能正常感知 EOF。
	// CancelRead 同时取消接收方向，防止对端继续发送数据导致的半开流积压。
	qc.stream.CancelRead(0)
	return qc.stream.Close()
}

func (qc *quicStreamConn) SetDeadline(t time.Time) error {
	return qc.stream.SetDeadline(t)
}

func (qc *quicStreamConn) SetReadDeadline(t time.Time) error {
	return qc.stream.SetReadDeadline(t)
}

func (qc *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return qc.stream.SetWriteDeadline(t)
}
