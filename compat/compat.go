package compat

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/zijiren233/gwst/internal/dialer"
	"github.com/zijiren233/gwst/internal/transport"
	"github.com/zijiren233/gwst/internal/tunnel"
)

// Re-export types from tunnel package for backward compatibility
type Handler = tunnel.Handler
type NamedTarget = tunnel.NamedTarget
type GetTargetFunc = tunnel.GetTargetFunc
type HandlerOption = tunnel.HandlerOption

// Re-export types from dialer package for backward compatibility
type Forwarder = dialer.Forwarder
type ForwarderOption = dialer.ForwarderOption

// Dialer type for backward compatibility with new Client
// Note: This is defined in wsd.go, not an alias to dialer.Client

// Re-export constructor functions
var (
	NewHandler                        = tunnel.NewHandler
	WithHandlerLogger                 = tunnel.WithHandlerLogger
	WithHandlerGetTargetFunc          = tunnel.WithHandlerGetTargetFunc
	WithHandlerDefaultTargetAddr      = tunnel.WithHandlerDefaultTargetAddr
	WithHandlerFallbackAddrs          = tunnel.WithHandlerFallbackAddrs
	WithHandlerAllowedTargets         = tunnel.WithHandlerAllowedTargets
	WithHandlerNamedTargets           = tunnel.WithHandlerNamedTargets
	WithHandlerBufferSize             = tunnel.WithHandlerBufferSize
	WithHandlerLoadBalance            = tunnel.WithHandlerLoadBalance
	WithHandlerUDPDialReadTimeout     = tunnel.WithHandlerUDPDialReadTimeout
	WithHandlerUDPIdleTimeout         = tunnel.WithHandlerUDPIdleTimeout
	WithHandlerDisableTCPProtocol     = tunnel.WithHandlerDisableTCPProtocol
	WithHandlerDisableUDPProtocol     = tunnel.WithHandlerDisableUDPProtocol
	WithHandlerUDPEarlyDataHeaderName = tunnel.WithHandlerUDPEarlyDataHeaderName
	WithHandlerKey                    = tunnel.WithHandlerKey
	WithHandlerCryptoManager          = tunnel.WithHandlerCryptoManager
	BalanceTargets                    = tunnel.BalanceTargets

	// Dialer package exports
	NewForwarder               = dialer.NewForwarder
	WithLogger                 = dialer.WithLogger
	WithDisableTCP             = dialer.WithDisableTCP
	WithDisableUDP             = dialer.WithDisableUDP
	WithUDPPool                = dialer.WithUDPPool
	WithUDPPoolSize            = dialer.WithUDPPoolSize
	WithUDPPoolPreAlloc        = dialer.WithUDPPoolPreAlloc
	WithBufferSize             = dialer.WithBufferSize
	WithUDPCleanupInterval     = dialer.WithUDPCleanupInterval
	WithUDPIdleTimeout         = dialer.WithUDPIdleTimeout
	WithDisableUDPEarlyData    = dialer.WithDisableUDPEarlyData
	WithUDPEarlyDataHeaderName = dialer.WithUDPEarlyDataHeaderName
	WithMaxEarlyDataSize       = dialer.WithMaxEarlyDataSize
	WithCryptoManager          = dialer.WithCryptoManager
)

// balanceTargets is an alias for backward compatibility
var balanceTargets = BalanceTargets

type Server struct {
	listener              net.Listener
	listenErr             error
	shutdowned            chan struct{}
	onListened            chan struct{}
	server                *http.Server              // for WebSocket
	serverTransport       transport.ServerTransport // for TCP/QUIC
	wsHandler             *Handler
	tlsConfig             *tls.Config
	path                  string
	certFile              string
	keyFile               string
	serverName            string
	listenAddr            string
	selfSignedCertOptions []SelfSignedCertOption
	waitListenCloseOnce   sync.Once
	tls                   bool
	transport             string // "websocket", "tcp", or "quic"
}

type ServerOption func(*Server)

func WithListener(listener net.Listener) ServerOption {
	return func(ps *Server) {
		ps.listener = listener
	}
}

func WithListenAddr(listenAddr string) ServerOption {
	return func(ps *Server) {
		ps.listenAddr = listenAddr
	}
}

func WithTLS(certFile, keyFile string) ServerOption {
	return func(ps *Server) {
		ps.tls = true
		ps.certFile = certFile
		ps.keyFile = keyFile
	}
}

func WithServerName(serverName string) ServerOption {
	return func(ps *Server) {
		ps.serverName = serverName
	}
}

func WithTLSConfig(tlsConfig *tls.Config) ServerOption {
	return func(ps *Server) {
		if tlsConfig != nil {
			ps.tls = true
			ps.tlsConfig = tlsConfig
		}
	}
}

func WithSelfSignedCert(opts ...SelfSignedCertOption) ServerOption {
	return func(ps *Server) {
		ps.selfSignedCertOptions = opts
	}
}

func WithTransport(transport string) ServerOption {
	return func(ps *Server) {
		ps.transport = transport
	}
}

func NewServer(path string, wsHandler *Handler, opts ...ServerOption) *Server {
	ps := &Server{
		wsHandler:  wsHandler,
		path:       path,
		onListened: make(chan struct{}),
		shutdowned: make(chan struct{}),
		transport:  "websocket",
	}

	for _, opt := range opts {
		opt(ps)
	}

	return ps
}

func (ps *Server) closeWaitListen() {
	ps.waitListenCloseOnce.Do(func() {
		close(ps.onListened)
	})
}

func (ps *Server) WaitListen() error {
	<-ps.onListened
	return ps.listenErr
}

func (ps *Server) WaitShutdown() {
	<-ps.shutdowned
}

func (ps *Server) Serve() error {
	if ps.transport == "tcp" || ps.transport == "quic" {
		return ps.serveWithTransport()
	}

	server := ps.Server()

	defer ps.closeWaitListen()
	defer close(ps.shutdowned)

	if ps.tls {
		return ps.listenAndServeTLS(server)
	}

	return ps.listenAndServe(server)
}

func (ps *Server) listenAndServeTLS(server *http.Server) error {
	if ps.tlsConfig == nil && ps.certFile == "" && ps.keyFile == "" {
		cert, err := GenerateSelfSignedCert(ps.serverName, ps.selfSignedCertOptions...)
		if err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}

		ps.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{*cert},
			MinVersion:   tls.VersionTLS13,
		}
	}

	if ps.tlsConfig != nil && ps.tlsConfig.ServerName == "" {
		ps.tlsConfig.ServerName = ps.serverName
	}

	ln, err := ps.getListener()
	if err != nil {
		ps.listenErr = err
		return err
	}
	defer ln.Close()

	ps.closeWaitListen()

	server.TLSConfig = ps.tlsConfig

	return server.ServeTLS(ln, ps.certFile, ps.keyFile)
}

func (ps *Server) getListener() (net.Listener, error) {
	if ps.listener != nil {
		return ps.listener, nil
	}

	addr := ps.listenAddr
	if addr == "" {
		if ps.tls {
			addr = ":https"
		} else {
			addr = ":http"
		}
	}

	return net.Listen("tcp", addr)
}

func (ps *Server) listenAndServe(server *http.Server) error {
	ln, err := ps.getListener()
	if err != nil {
		ps.listenErr = err
		return err
	}
	defer ln.Close()

	ps.closeWaitListen()

	return server.Serve(ln)
}

func (ps *Server) Server() *http.Server {
	if ps.server == nil {
		mux := http.NewServeMux()
		mux.Handle(ps.path, ps.wsHandler)
		ps.server = &http.Server{
			Addr:              ps.listenAddr,
			Handler:           mux,
			ReadHeaderTimeout: time.Second * 5,
			MaxHeaderBytes:    16 * 1024,
		}
		ps.server.RegisterOnShutdown(func() {
			ps.wsHandler.Close()
		})
	}

	return ps.server
}

func (ps *Server) Close() error {
	defer ps.closeWaitListen()

	if ps.serverTransport != nil {
		return ps.serverTransport.Close()
	}

	if ps.server != nil {
		ps.wsHandler.Close()
		return ps.server.Close()
	}

	return nil
}

func (ps *Server) Shutdown(ctx context.Context) error {
	defer ps.closeWaitListen()
	defer ps.wsHandler.Wait()

	if ps.serverTransport != nil {
		return ps.serverTransport.Close()
	}

	if ps.server != nil {
		return ps.server.Shutdown(ctx)
	}

	return nil
}

// serveWithTransport 使用 transport 包处理 TCP 和 QUIC 传输
func (ps *Server) serveWithTransport() error {
	defer ps.closeWaitListen()
	defer close(ps.shutdowned)

	// 将 transport 字符串转换为 TransportType
	var transportType transport.TransportType
	switch ps.transport {
	case "tcp":
		transportType = transport.TransportTCP
	case "quic":
		transportType = transport.TransportQUIC
	default:
		ps.listenErr = fmt.Errorf("unsupported transport type: %s", ps.transport)
		return ps.listenErr
	}

	// 创建传输配置
	cfg := transport.TransportServerConfig{
		Type:       transportType,
		ListenAddr: ps.listenAddr,
		Handler:    ps.createTransportHandler(),
		TLS:        ps.tls,
		CertFile:   ps.certFile,
		KeyFile:    ps.keyFile,
		Logger:     transport.NewSafeLoggerOrNull(nil),
	}

	// 创建传输管理器
	tm := transport.NewTransportManager()

	// 创建服务端传输
	serverTransport, err := tm.CreateServerTransport(cfg)
	if err != nil {
		ps.listenErr = err
		return err
	}

	// 保存引用以便 Close() 时使用
	ps.serverTransport = serverTransport

	// 等待监听完成
	go func() {
		if err := serverTransport.WaitListen(); err != nil {
			ps.listenErr = err
		}
		ps.closeWaitListen()
	}()

	// 启动服务
	return serverTransport.Serve()
}

// createTransportHandler 创建一个适配器函数，将 Handler 适配到 transport.Handler 接口
func (ps *Server) createTransportHandler() func(net.Conn) error {
	return func(conn net.Conn) error {
		defer conn.Close()

		// 从连接中读取协议标识字节（5 秒超时，防止半开连接长期占用 goroutine）
		// 0x01 = TCP, 0x02 = UDP
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return fmt.Errorf("failed to set protocol byte deadline: %w", err)
		}
		var protocolByte [1]byte
		if _, err := conn.Read(protocolByte[:]); err != nil {
			return fmt.Errorf("failed to read protocol byte: %w", err)
		}
		conn.SetReadDeadline(time.Time{})

		protocol := "tcp"
		if protocolByte[0] == 0x02 {
			protocol = "udp"
		}

		// 获取目标地址
		target := ps.wsHandler.GetDefaultTarget()
		fallbackAddrs := ps.wsHandler.GetFallbackAddrs()

		if target == "" && len(fallbackAddrs) == 0 {
			return fmt.Errorf("no target configured")
		}

		if target == "" && len(fallbackAddrs) > 0 {
			target = fallbackAddrs[0]
			fallbackAddrs = fallbackAddrs[1:]
		}

		// 调用 Handler 的内部处理逻辑
		return ps.wsHandler.HandleRawConnection(conn, protocol, target, fallbackAddrs)
	}
}
