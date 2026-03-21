package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
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
		NextProtos:   []string{"gwst-quic"},
		MinVersion:   tls.VersionTLS13,
	}

	// Create QUIC listener
	listener, err := quic.ListenAddr(qst.config.ListenAddr, tlsConfig, &quic.Config{
		MaxIdleTimeout:  time.Minute * 5,
		KeepAlivePeriod: time.Second * 30,
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
		conn, err := listener.Accept(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return nil
			}
			qst.config.Logger.Errorf("Failed to accept QUIC connection: %v", err)
			continue
		}

		qst.connectionWg.Add(1)
		go qst.handleConnection(conn)
	}
}

// handleConnection 处理单个 QUIC 连接
func (qst *QUICServerTransport) handleConnection(conn quic.Connection) {
	defer qst.connectionWg.Done()
	defer conn.CloseWithError(0, "connection closed")

	// Accept streams
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}

		// Handle each stream as a separate connection
		go func(s quic.Stream) {
			defer s.Close()
			if err := qst.config.Handler(&quicStreamWrapper{Stream: s}); err != nil {
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
		if qst.listener != nil {
			qst.listener.Close()
		}

		// Wait for all connections to close
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

// QUICClientTransport QUIC 客户端传输实现
type QUICClientTransport struct {
	config TransportClientConfig
	mu     sync.Mutex
	closed bool
}

// NewQUICClientTransport 创建 QUIC 客户端传输
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

	return &QUICClientTransport{
		config: cfg,
	}, nil
}

// Dial 建立 QUIC 连接
func (qct *QUICClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	qct.mu.Lock()
	defer qct.mu.Unlock()

	if qct.closed {
		return nil, net.ErrClosed
	}

	tlsConfig := &tls.Config{
		ServerName:         qct.config.ServerName,
		InsecureSkipVerify: qct.config.Insecure,
		NextProtos:         []string{"gwst-quic"},
		MinVersion:         tls.VersionTLS13,
	}

	quicConf := &quic.Config{
		MaxIdleTimeout:  time.Minute * 5,
		KeepAlivePeriod: time.Second * 30,
	}

	var conn quic.Connection
	var err error

	// 使用自定义 ListenConfig 创建受保护的 UDP socket（Android VPN 场景）
	if qct.config.ListenConfig != nil {
		var pconn net.PacketConn
		pconn, err = qct.config.ListenConfig.ListenPacket(ctx, "udp", "")
		if err != nil {
			return nil, fmt.Errorf("failed to create UDP socket: %w", err)
		}
		tr := &quic.Transport{Conn: pconn}
		addr, resolveErr := net.ResolveUDPAddr("udp", qct.config.RemoteAddr)
		if resolveErr != nil {
			pconn.Close()
			return nil, fmt.Errorf("failed to resolve remote addr: %w", resolveErr)
		}
		conn, err = tr.Dial(ctx, addr, tlsConfig, quicConf)
		if err != nil {
			pconn.Close()
			return nil, err
		}
	} else {
		conn, err = quic.DialAddr(ctx, qct.config.RemoteAddr, tlsConfig, quicConf)
		if err != nil {
			return nil, err
		}
	}

	// Open a new stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "failed to open stream")
		return nil, err
	}

	return &quicStreamConn{
		stream: stream,
		conn:   conn,
	}, nil
}

// Close 关闭 QUIC 连接
func (qct *QUICClientTransport) Close() error {
	qct.mu.Lock()
	defer qct.mu.Unlock()

	if qct.closed {
		return nil
	}

	qct.closed = true
	return nil
}

// quicStreamWrapper wraps a QUIC stream to implement net.Conn
type quicStreamWrapper struct {
	Stream quic.Stream
}

func (q *quicStreamWrapper) Read(b []byte) (int, error) {
	return q.Stream.Read(b)
}

func (q *quicStreamWrapper) Write(b []byte) (int, error) {
	return q.Stream.Write(b)
}

func (q *quicStreamWrapper) Close() error {
	return q.Stream.Close()
}

func (q *quicStreamWrapper) LocalAddr() net.Addr {
	// QUIC streams don't have direct addresses, return nil
	return nil
}

func (q *quicStreamWrapper) RemoteAddr() net.Addr {
	// QUIC streams don't have direct addresses, return nil
	return nil
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
	stream quic.Stream
	conn   quic.Connection
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
	// Close the stream
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
