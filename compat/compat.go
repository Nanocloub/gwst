package compat

import (
	"context"
	"crypto/tls"
	"errors"
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
	listener            net.Listener
	listenErr           error
	shutdowned          chan struct{}
	onListened          chan struct{}
	server              *http.Server              // for WebSocket
	serverTransport     transport.ServerTransport // for TCP/QUIC
	wsHandler           *Handler
	tlsConfig           *tls.Config
	path                string
	certFile            string
	keyFile             string
	serverName          string
	listenAddr          string
	waitListenCloseOnce sync.Once
	tls                 bool
	transport           string // "websocket", "tcp", or "quic"
	// QUIC 接收窗口大小（字节），0 表示使用 quic-go 默认值
	quicInitialStreamRecvWindow uint64
	quicMaxStreamRecvWindow     uint64
	quicInitialConnRecvWindow   uint64
	quicMaxConnRecvWindow       uint64
	// QUIC 额外配置
	quicMaxIdleTimeout          time.Duration
	quicMaxIncomingStreams      int64
	quicInitialPacketSize       uint16
	quicDisablePathMTUDiscovery bool
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

func WithTransport(transport string) ServerOption {
	return func(ps *Server) {
		ps.transport = transport
	}
}

// WithQUICWindowSizes 设置 QUIC 接收窗口大小。
// initialStream/maxStream 控制每条流的接收窗口，initialConn/maxConn 控制整个连接的接收窗口。
// 0 表示保持 quic-go 默认值（stream: 512KB/6MB，conn: 512KB/15MB）。
func WithQUICWindowSizes(initialStream, maxStream, initialConn, maxConn uint64) ServerOption {
	return func(ps *Server) {
		ps.quicInitialStreamRecvWindow = initialStream
		ps.quicMaxStreamRecvWindow = maxStream
		ps.quicInitialConnRecvWindow = initialConn
		ps.quicMaxConnRecvWindow = maxConn
	}
}

// WithQUICMaxIdleTimeout 设置 QUIC 连接最大空闲超时。0 表示使用默认值（2分钟）。
func WithQUICMaxIdleTimeout(d time.Duration) ServerOption {
	return func(ps *Server) {
		ps.quicMaxIdleTimeout = d
	}
}

// WithQUICMaxIncomingStreams 设置 QUIC 服务端允许对端打开的最大双向流数。0 表示使用默认值（100）。
func WithQUICMaxIncomingStreams(n int64) ServerOption {
	return func(ps *Server) {
		ps.quicMaxIncomingStreams = n
	}
}

// WithQUICInitialPacketSize 设置 QUIC 初始包大小（字节）。取值范围：[1200, 1452]，0 表示使用默认值（1452）。
func WithQUICInitialPacketSize(size uint16) ServerOption {
	return func(ps *Server) {
		ps.quicInitialPacketSize = size
	}
}

// WithQUICDisablePathMTUDiscovery 设置是否禁用 QUIC 路径 MTU 探测。
func WithQUICDisablePathMTUDiscovery(v bool) ServerOption {
	return func(ps *Server) {
		ps.quicDisablePathMTUDiscovery = v
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
		ps.listenErr = errors.New("TLS requires either WithTLSConfig or WithTLS(certFile, keyFile)")
		return ps.listenErr
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

	// Go 的 http.Server.ServeTLS 会将 listener 包裹为 TLS listener，导致
	// Serve() 内部的 *net.TCPListener 断言失败，自动 keepalive 不生效。
	// 用 tcpKeepAliveListener 包裹后，Accept() 在 TLS 升级前就已启用 keepalive。
	ln = tcpKeepAliveListener{ln}

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

	// 用 tcpKeepAliveListener 包裹，覆盖 Go http.Server 默认 3 分钟的 keepalive 周期，
	// 统一为 30s，与 TCP/QUIC 隧道一致。
	ln = tcpKeepAliveListener{ln}

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
		Type:                           transportType,
		ListenAddr:                     ps.listenAddr,
		Handler:                        ps.createTransportHandler(),
		TLS:                            ps.tls,
		CertFile:                       ps.certFile,
		KeyFile:                        ps.keyFile,
		Logger:                         transport.NewSafeLoggerOrNull(nil),
		QUICInitialStreamReceiveWindow: ps.quicInitialStreamRecvWindow,
		QUICMaxStreamReceiveWindow:     ps.quicMaxStreamRecvWindow,
		QUICInitialConnReceiveWindow:   ps.quicInitialConnRecvWindow,
		QUICMaxConnReceiveWindow:       ps.quicMaxConnRecvWindow,
		QUICMaxIdleTimeout:             ps.quicMaxIdleTimeout,
		QUICMaxIncomingStreams:         ps.quicMaxIncomingStreams,
		QUICInitialPacketSize:          ps.quicInitialPacketSize,
		QUICDisablePathMTUDiscovery:    ps.quicDisablePathMTUDiscovery,
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

// tcpKeepAliveListener 包装 net.Listener，在每个 Accept 的连接上启用 OS TCP keepalive（30s 周期）。
// http.Server.ServeTLS 会将 listener 包为 TLS listener，导致 Go 内部的 *net.TCPListener 断言失败，
// 自动 keepalive 不生效；本 wrapper 在 TLS 升级前设置，确保 TLS/非 TLS 场景均生效。
type tcpKeepAliveListener struct {
	net.Listener
}

func (ln tcpKeepAliveListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	return conn, nil
}
