package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// TCPServerTransport TCP 服务端传输实现
type TCPServerTransport struct {
	listener     net.Listener
	listenErr    error
	onListened   chan struct{}
	shutdowned   chan struct{}
	config       TransportServerConfig
	connectionWg sync.WaitGroup
	onListenOnce sync.Once
	shutdownOnce sync.Once
	closeChan    chan struct{}
}

// NewTCPServerTransport 创建 TCP 服务端传输
func NewTCPServerTransport(cfg TransportServerConfig) (*TCPServerTransport, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("listen_addr is required")
	}

	if cfg.Handler == nil {
		return nil, errors.New("handler is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	return &TCPServerTransport{
		onListened: make(chan struct{}),
		shutdowned: make(chan struct{}),
		closeChan:  make(chan struct{}),
		config:     cfg,
	}, nil
}

// Serve 启动 TCP 服务
func (tst *TCPServerTransport) Serve() error {
	defer tst.onListenOnce.Do(func() {
		close(tst.onListened)
	})
	defer tst.shutdownOnce.Do(func() {
		close(tst.shutdowned)
	})

	var tlsConfig *tls.Config
	if tst.config.TLS {
		if tst.config.CertFile == "" || tst.config.KeyFile == "" {
			tst.listenErr = errors.New("cert_file and key_file are required for TLS")
			return tst.listenErr
		}

		cert, err := tls.LoadX509KeyPair(tst.config.CertFile, tst.config.KeyFile)
		if err != nil {
			tst.listenErr = fmt.Errorf("failed to load TLS certificates: %w", err)
			return tst.listenErr
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	// 使用 net.ListenTCP 以便 AcceptTCP() 获取 *net.TCPConn，
	// 从而在连接建立时立即开启 TCP keepalive，确保异常断开的客户端
	// 能在 ~90s 内被检测到（3×30s 探测），避免 gwst→后端连接无限积压。
	tcpAddr, err := net.ResolveTCPAddr("tcp", tst.config.ListenAddr)
	if err != nil {
		tst.listenErr = fmt.Errorf("failed to resolve address: %w", err)
		return tst.listenErr
	}

	tcpListener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		tst.listenErr = fmt.Errorf("failed to listen: %w", err)
		return tst.listenErr
	}

	tst.listener = tcpListener

	tst.onListenOnce.Do(func() {
		close(tst.onListened)
	})

	protocol := "TCP"
	if tst.config.TLS {
		protocol = "TCP+TLS"
	}
	tst.config.Logger.Infof("%s server listening on %s", protocol, tst.config.ListenAddr)

	// Accept connections
	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			select {
			case <-tst.closeChan:
				return nil
			default:
				if errors.Is(err, net.ErrClosed) {
					return nil
				}
				tst.config.Logger.Infof("Accept error: %v", err)
				continue
			}
		}

		// 开启 TCP keepalive：OS 将在 30s 空闲后每 30s 发送 keepalive 探测，
		// 3 次无响应（约 90s）后判定对端死亡并触发 ECONNRESET/EOF，
		// 使 gwst 的 goroutine 及时退出并释放后端连接。
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)

		var conn net.Conn = tcpConn
		if tlsConfig != nil {
			conn = tls.Server(tcpConn, tlsConfig)
		}

		tst.connectionWg.Add(1)
		go func(conn net.Conn) {
			defer tst.connectionWg.Done()
			defer conn.Close()

			if err := tst.config.Handler(conn); err != nil {
				tst.config.Logger.Infof("Connection handler error: %v", err)
			}
		}(conn)
	}
}

// WaitListen 等待服务启动
func (tst *TCPServerTransport) WaitListen() error {
	<-tst.onListened
	return tst.listenErr
}

// WaitShutdown 等待服务关闭
func (tst *TCPServerTransport) WaitShutdown() <-chan struct{} {
	return tst.shutdowned
}

// Close 关闭 TCP 服务
func (tst *TCPServerTransport) Close() error {
	tst.shutdownOnce.Do(func() {
		close(tst.closeChan)

		if tst.listener != nil {
			tst.listener.Close()
		}

		// Wait for all connections to close
		done := make(chan struct{})
		go func() {
			tst.connectionWg.Wait()
			close(done)
		}()

		// 使用 Timer 而不是 time.After，避免泄漏
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()

		select {
		case <-done:
		case <-timer.C:
		}

		close(tst.shutdowned)
	})

	return nil
}

// TCPClientTransport TCP 客户端传输实现
type TCPClientTransport struct {
	config TransportClientConfig
	dialer *net.Dialer // 预构建，不可变
	tlsCfg *tls.Config // 预构建，不可变；nil 表示无 TLS
	mu     sync.Mutex
	closed bool
}

// NewTCPClientTransport 创建 TCP 客户端传输
func NewTCPClientTransport(cfg TransportClientConfig) (*TCPClientTransport, error) {
	if cfg.RemoteAddr == "" {
		return nil, errors.New("remote_addr is required")
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	dialer := cfg.Dialer
	if dialer == nil {
		dialer = &net.Dialer{
			Timeout: 5 * time.Second,
		}
	}

	var tlsCfg *tls.Config
	if cfg.TLS {
		tlsCfg = &tls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: cfg.Insecure,
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
	}

	return &TCPClientTransport{
		config: cfg,
		dialer: dialer,
		tlsCfg: tlsCfg,
	}, nil
}

// Dial 建立 TCP 连接。
//
// 并发安全：mu 仅用于保护 closed 字段，在 I/O 操作（DialContext / TLS
// Handshake）期间不持锁，允许多个 goroutine 并发建立连接。
func (tct *TCPClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	tct.mu.Lock()
	if tct.closed {
		tct.mu.Unlock()
		return nil, net.ErrClosed
	}
	tct.mu.Unlock() // 释放锁，后续 I/O 不持锁

	if ctx == nil {
		ctx = context.Background()
	}

	conn, err := tct.dialer.DialContext(ctx, "tcp", tct.config.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// 启用 OS keepalive：检测 TCP 隧道死连接，防止 v2bx goroutine 积压。
	// 必须在 TLS 握手前设置，握手后 *net.TCPConn 已被 tls.Conn 包裹而无法断言。
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	if tct.tlsCfg != nil {
		// tls.Client 复用预构建的 tlsCfg（不可变），无需每次分配
		tlsConn := tls.Client(conn, tct.tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

// Close 关闭 TCP 传输（标记为关闭；各连接在 handler 层面由调用方关闭）
func (tct *TCPClientTransport) Close() error {
	tct.mu.Lock()
	defer tct.mu.Unlock()

	tct.closed = true
	return nil
}
