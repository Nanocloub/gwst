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

	var listener net.Listener
	var err error

	if tst.config.TLS {
		if tst.config.CertFile == "" || tst.config.KeyFile == "" {
			tst.listenErr = errors.New("cert_file and key_file are required for TLS")
			return tst.listenErr
		}

		tlsConfig, err := tls.LoadX509KeyPair(tst.config.CertFile, tst.config.KeyFile)
		if err != nil {
			tst.listenErr = fmt.Errorf("failed to load TLS certificates: %w", err)
			return tst.listenErr
		}

		tcpListener, err := net.Listen("tcp", tst.config.ListenAddr)
		if err != nil {
			tst.listenErr = fmt.Errorf("failed to listen: %w", err)
			return tst.listenErr
		}

		listener = tls.NewListener(tcpListener, &tls.Config{
			Certificates: []tls.Certificate{tlsConfig},
			MinVersion:   tls.VersionTLS13,
		})
	} else {
		listener, err = net.Listen("tcp", tst.config.ListenAddr)
		if err != nil {
			tst.listenErr = fmt.Errorf("failed to listen: %w", err)
			return tst.listenErr
		}
	}

	tst.listener = listener

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
		conn, err := listener.Accept()
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
	conn   net.Conn
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

	return &TCPClientTransport{
		config: cfg,
	}, nil
}

// Dial 建立 TCP 连接
func (tct *TCPClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	tct.mu.Lock()
	defer tct.mu.Unlock()

	if tct.closed {
		return nil, net.ErrClosed
	}

	dialer := &net.Dialer{
		Timeout: time.Second * 5,
	}

	if ctx == nil {
		ctx = context.Background()
	}

	conn, err := dialer.DialContext(ctx, "tcp", tct.config.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}

	// Handle TLS if needed
	if tct.config.TLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         tct.config.ServerName,
			InsecureSkipVerify: tct.config.Insecure,
			MinVersion:         tls.VersionTLS13,
		})

		// Perform handshake
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		tct.conn = tlsConn
	} else {
		tct.conn = conn
	}

	return tct.conn, nil
}

// Close 关闭 TCP 连接
func (tct *TCPClientTransport) Close() error {
	tct.mu.Lock()
	defer tct.mu.Unlock()

	if tct.closed {
		return nil
	}

	tct.closed = true

	if tct.conn != nil {
		return tct.conn.Close()
	}

	return nil
}
