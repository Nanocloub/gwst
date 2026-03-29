package transport

import (
	"fmt"
	"sync"
)

// TransportManager 传输管理器
type TransportManager struct {
	serverFactories map[TransportType]ServerTransportFactory
	clientFactories map[TransportType]ClientTransportFactory
}

// NewTransportManager 创建新的传输管理器
func NewTransportManager() *TransportManager {
	tm := &TransportManager{
		serverFactories: make(map[TransportType]ServerTransportFactory),
		clientFactories: make(map[TransportType]ClientTransportFactory),
	}

	// Register default transports
	tm.registerWebSocketTransport()
	tm.registerTCPTransport()
	tm.registerQUICTransport()

	return tm
}

// RegisterServerTransport 注册服务端传输工厂
func (tm *TransportManager) RegisterServerTransport(transportType TransportType, factory ServerTransportFactory) {
	tm.serverFactories[transportType] = factory
}

// RegisterClientTransport 注册客户端传输工厂
func (tm *TransportManager) RegisterClientTransport(transportType TransportType, factory ClientTransportFactory) {
	tm.clientFactories[transportType] = factory
}

// CreateServerTransport 创建服务端传输
func (tm *TransportManager) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	if cfg.Type == "" {
		cfg.Type = TransportWebSocket
	}

	if !IsValidTransport(cfg.Type) {
		return nil, fmt.Errorf("unknown transport type: %s", cfg.Type)
	}

	factory, ok := tm.serverFactories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("server transport factory not found for type: %s", cfg.Type)
	}

	return factory.CreateServerTransport(cfg)
}

// CreateClientTransport 创建客户端传输
func (tm *TransportManager) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	if cfg.Type == "" {
		cfg.Type = TransportWebSocket
	}

	if !IsValidTransport(cfg.Type) {
		return nil, fmt.Errorf("unknown transport type: %s", cfg.Type)
	}

	factory, ok := tm.clientFactories[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("client transport factory not found for type: %s", cfg.Type)
	}

	return factory.CreateClientTransport(cfg)
}

// registerWebSocketTransport 注册 WebSocket 传输
func (tm *TransportManager) registerWebSocketTransport() {
	tm.RegisterServerTransport(TransportWebSocket, &webSocketServerFactory{})
	tm.RegisterClientTransport(TransportWebSocket, &webSocketClientFactory{})
}

// registerTCPTransport 注册 TCP 传输
func (tm *TransportManager) registerTCPTransport() {
	tm.RegisterServerTransport(TransportTCP, &tcpServerFactory{})
	tm.RegisterClientTransport(TransportTCP, &tcpClientFactory{})
}

// registerQUICTransport 注册 QUIC 传输
func (tm *TransportManager) registerQUICTransport() {
	tm.RegisterServerTransport(TransportQUIC, &quicServerFactory{})
	tm.RegisterClientTransport(TransportQUIC, &quicClientFactory{})
}

// WebSocket 传输工厂实现

type webSocketServerFactory struct{}

func (f *webSocketServerFactory) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	return NewWebSocketServerTransport(cfg)
}

type webSocketClientFactory struct{}

func (f *webSocketClientFactory) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	return NewWebSocketClientTransport(cfg)
}

// TCP 传输工厂实现

type tcpServerFactory struct{}

func (f *tcpServerFactory) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	return NewTCPServerTransport(cfg)
}

type tcpClientFactory struct{}

func (f *tcpClientFactory) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	return NewTCPClientTransport(cfg)
}

// QUIC 传输工厂实现
//
// quicClientFactory 缓存 QUICClientTransport 实例，使同一 (remoteAddr, serverName,
// insecure) 组合的多次 Dial 共用同一持久 QUIC 连接（stream multiplexing）。
// 无需每次建隧道都执行 TLS 握手。

type quicServerFactory struct{}

func (f *quicServerFactory) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	return NewQUICServerTransport(cfg)
}

type quicClientFactory struct {
	mu    sync.Mutex
	cache map[string]*QUICClientTransport
}

func (f *quicClientFactory) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	// 缓存键：区分不同的远端地址、TLS 参数和 QUIC 窗口/超时配置
	key := fmt.Sprintf("%s|%s|%v|%d|%d|%d|%d|%d|%v|%d",
		cfg.RemoteAddr, cfg.ServerName, cfg.Insecure,
		cfg.QUICInitialStreamReceiveWindow, cfg.QUICMaxStreamReceiveWindow,
		cfg.QUICInitialConnReceiveWindow, cfg.QUICMaxConnReceiveWindow,
		cfg.QUICMaxIdleTimeout, cfg.QUICDisablePathMTUDiscovery,
		cfg.QUICInitialPacketSize,
	)

	f.mu.Lock()
	if f.cache == nil {
		f.cache = make(map[string]*QUICClientTransport)
	}
	t, ok := f.cache[key]
	f.mu.Unlock()

	if ok {
		t.mu.Lock()
		alive := t.isAlive()
		t.mu.Unlock()
		if alive {
			return t, nil
		}
	}

	// 创建新 transport（可能与并发 goroutine 竞争，用二次检查解决）
	newT, err := NewQUICClientTransport(cfg)
	if err != nil {
		return nil, err
	}

	// 二次检查：另一个 goroutine 可能已经创建了新的有效 transport。
	// 注意：不使用 defer 释放锁，以便在锁外关闭失效的旧 transport（Close 含网络 I/O）。
	f.mu.Lock()
	var stale *QUICClientTransport
	if existing, ok := f.cache[key]; ok {
		existing.mu.Lock()
		alive := existing.isAlive()
		existing.mu.Unlock()
		if alive {
			f.mu.Unlock()
			return existing, nil
		}
		stale = existing
	}
	f.cache[key] = newT
	f.mu.Unlock()

	// 在锁外关闭失效的旧 transport，避免 QUIC 连接资源（socket、goroutine）泄漏。
	if stale != nil {
		stale.Close()
	}
	return newT, nil
}

var globalTransportManager = NewTransportManager()

// GetTransportManager 获取全局传输管理器
func GetTransportManager() *TransportManager {
	return globalTransportManager
}
