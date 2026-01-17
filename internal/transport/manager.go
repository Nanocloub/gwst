package transport

import (
	"fmt"
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

type quicServerFactory struct{}

func (f *quicServerFactory) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	return NewQUICServerTransport(cfg)
}

type quicClientFactory struct{}

func (f *quicClientFactory) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	return NewQUICClientTransport(cfg)
}

// Global transport manager
var globalTransportManager = NewTransportManager()

// GetTransportManager 获取全局传输管理器
func GetTransportManager() *TransportManager {
	return globalTransportManager
}
