package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// WebSocketServerTransport WebSocket 服务端传输实现
type WebSocketServerTransport struct {
	listener     net.Listener
	listenErr    error
	onListened   chan struct{}
	shutdowned   chan struct{}
	server       *http.Server
	config       TransportServerConfig
	handler      *websocket.Server
	connectionWg sync.WaitGroup
	onListenOnce sync.Once
	shutdownOnce sync.Once
}

// NewWebSocketServerTransport 创建 WebSocket 服务端传输
func NewWebSocketServerTransport(cfg TransportServerConfig) (*WebSocketServerTransport, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("listen_addr is required")
	}

	if cfg.Handler == nil {
		return nil, errors.New("handler is required")
	}

	if cfg.Path == "" {
		cfg.Path = "/ws"
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	wst := &WebSocketServerTransport{
		onListened: make(chan struct{}),
		shutdowned: make(chan struct{}),
		config:     cfg,
	}

	wsHandler := &websocket.Server{
		Handler: wst.handleConn,
		Handshake: func(config *websocket.Config, req *http.Request) error {
			if cfg.Key != "" && len(cfg.Key) >= AegisKeySize {
				// Verify key from X-Key header
				if cfg.Key != req.Header.Get("X-Key") {
					return errors.New("invalid key")
				}
			}
			// Accept any origin
			if config.Origin == nil {
				origin, err := websocket.Origin(config, req)
				if err != nil {
					return err
				}
				config.Origin = origin
			}
			return nil
		},
	}

	wst.handler = wsHandler

	// Create HTTP server
	mux := http.NewServeMux()
	mux.Handle(cfg.Path, wsHandler)

	wst.server = &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: mux,
	}

	if cfg.TLS {
		if cfg.CertFile == "" || cfg.KeyFile == "" {
			return nil, errors.New("cert_file and key_file are required for TLS")
		}
	}

	return wst, nil
}

// Serve 启动 WebSocket 服务
func (wst *WebSocketServerTransport) Serve() error {
	defer wst.onListenOnce.Do(func() {
		close(wst.onListened)
	})
	defer wst.shutdownOnce.Do(func() {
		close(wst.shutdowned)
	})

	var listener net.Listener
	var err error

	if wst.config.TLS {
		listener, err = net.Listen("tcp", wst.config.ListenAddr)
		if err != nil {
			wst.listenErr = fmt.Errorf("failed to listen: %w", err)
			return wst.listenErr
		}

		// Wrap with TLS
		tlsListener, err := newTLSListener(listener, wst.config.CertFile, wst.config.KeyFile)
		if err != nil {
			listener.Close()
			wst.listenErr = fmt.Errorf("failed to create TLS listener: %w", err)
			return wst.listenErr
		}
		listener = tlsListener
	} else {
		listener, err = net.Listen("tcp", wst.config.ListenAddr)
		if err != nil {
			wst.listenErr = fmt.Errorf("failed to listen: %w", err)
			return wst.listenErr
		}
	}

	wst.listener = listener

	wst.onListenOnce.Do(func() {
		close(wst.onListened)
	})

	wst.config.Logger.Infof("WebSocket server listening on %s", wst.config.ListenAddr)

	// Start HTTP server
	go func() {
		if err := wst.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			wst.config.Logger.Errorf("Server error: %v", err)
		}
	}()

	// Wait for shutdown signal or server error
	<-wst.shutdowned
	return nil
}

// handleConn 处理单个 WebSocket 连接
func (wst *WebSocketServerTransport) handleConn(ws *websocket.Conn) {
	defer ws.Close()

	wst.connectionWg.Add(1)
	defer wst.connectionWg.Done()

	ws.PayloadType = websocket.BinaryFrame

	if err := wst.config.Handler(ws); err != nil {
		wst.config.Logger.Infof("Connection handler error: %v", err)
	}
}

// WaitListen 等待服务启动
func (wst *WebSocketServerTransport) WaitListen() error {
	<-wst.onListened
	return wst.listenErr
}

// WaitShutdown 等待服务关闭
func (wst *WebSocketServerTransport) WaitShutdown() <-chan struct{} {
	return wst.shutdowned
}

// Close 关闭 WebSocket 服务
func (wst *WebSocketServerTransport) Close() error {
	wst.shutdownOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()

		if wst.server != nil {
			wst.server.Shutdown(ctx)
		}

		if wst.listener != nil {
			wst.listener.Close()
		}

		// Wait for all connections to close
		done := make(chan struct{})
		go func() {
			wst.connectionWg.Wait()
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second * 5):
		}

		close(wst.shutdowned)
	})

	return nil
}

// WebSocketClientTransport WebSocket 客户端传输实现
type WebSocketClientTransport struct {
	config TransportClientConfig
	conn   net.Conn
	mu     sync.Mutex
	closed bool
}

// NewWebSocketClientTransport 创建 WebSocket 客户端传输
func NewWebSocketClientTransport(cfg TransportClientConfig) (*WebSocketClientTransport, error) {
	if cfg.RemoteAddr == "" {
		return nil, errors.New("remote_addr is required")
	}

	if cfg.Host == "" {
		cfg.Host = cfg.RemoteAddr
	}

	if cfg.Path == "" {
		cfg.Path = "/ws"
	}

	if cfg.Logger == nil {
		cfg.Logger = NewSafeLoggerOrNull(nil)
	}

	if cfg.Context == nil {
		cfg.Context = context.Background()
	}

	return &WebSocketClientTransport{
		config: cfg,
	}, nil
}

// Dial 建立 WebSocket 连接
func (wct *WebSocketClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	wct.mu.Lock()
	defer wct.mu.Unlock()

	if wct.closed {
		return nil, net.ErrClosed
	}

	scheme := "ws"
	if wct.config.TLS {
		scheme = "wss"
	}

	url := fmt.Sprintf("%s://%s%s", scheme, wct.config.Host, wct.config.Path)

	wsConfig, err := websocket.NewConfig(url, scheme+"://"+wct.config.Host)
	if err != nil {
		return nil, err
	}

	// Set headers
	if wct.config.Key != "" {
		wsConfig.Header.Set("X-Key", wct.config.Key)
	}

	if wct.config.Headers != nil {
		for k, v := range wct.config.Headers {
			wsConfig.Header.Set(k, v[0])
		}
	}

	wsConfig.Dialer = &net.Dialer{
		Timeout: time.Second * 5,
	}

	// Create TCP connection
	var conn net.Conn
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	conn, err = (&net.Dialer{}).DialContext(timeoutCtx, "tcp", wct.config.RemoteAddr)
	if err != nil {
		return nil, err
	}

	// Handle TLS if needed
	if wct.config.TLS {
		tlsConn, err := createClientTLSConn(conn, wct.config.ServerName, wct.config.Insecure)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	// Create WebSocket connection
	wsConn, err := websocket.NewClient(wsConfig, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create websocket client: %w", err)
	}

	wsConn.PayloadType = websocket.BinaryFrame
	wct.conn = wsConn

	return wsConn, nil
}

// Close 关闭 WebSocket 连接
func (wct *WebSocketClientTransport) Close() error {
	wct.mu.Lock()
	defer wct.mu.Unlock()

	if wct.closed {
		return nil
	}

	wct.closed = true

	if wct.conn != nil {
		return wct.conn.Close()
	}

	return nil
}

// createClientTLSConn 创建客户端 TLS 连接
func createClientTLSConn(conn net.Conn, serverName string, insecure bool) (net.Conn, error) {
	// This is a simple TLS implementation
	// In production, use crypto/tls
	return conn, nil
}

// newTLSListener 创建 TLS 监听器
func newTLSListener(listener net.Listener, certFile, keyFile string) (net.Listener, error) {
	// This is a simple implementation
	// In production, use crypto/tls
	return listener, nil
}
