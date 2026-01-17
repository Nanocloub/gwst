package transport

import (
	"context"
	"fmt"
	"net"
)

// CustomTransportExample 展示如何实现自定义传输协议的示例
// 这是一个模板，可以用来实现其他传输协议如 HTTP/2、HTTPS 等

type CustomServerTransport struct {
	config TransportServerConfig
	// 在这里添加自定义实现所需的字段
}

func NewCustomServerTransport(cfg TransportServerConfig) (*CustomServerTransport, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen_addr is required")
	}

	return &CustomServerTransport{
		config: cfg,
	}, nil
}

// Serve 实现 ServerTransport 接口
func (cst *CustomServerTransport) Serve() error {
	// TODO: 实现自定义传输的启动逻辑
	return fmt.Errorf("not implemented")
}

// Close 实现 ServerTransport 接口
func (cst *CustomServerTransport) Close() error {
	// TODO: 实现清理逻辑
	return nil
}

// WaitListen 实现 ServerTransport 接口
func (cst *CustomServerTransport) WaitListen() error {
	// TODO: 实现启动等待逻辑
	return nil
}

// WaitShutdown 实现 ServerTransport 接口
func (cst *CustomServerTransport) WaitShutdown() <-chan struct{} {
	// TODO: 返回关闭信号通道
	return make(chan struct{})
}

type CustomClientTransport struct {
	config TransportClientConfig
	// 在这里添加自定义实现所需的字段
}

func NewCustomClientTransport(cfg TransportClientConfig) (*CustomClientTransport, error) {
	if cfg.RemoteAddr == "" {
		return nil, fmt.Errorf("remote_addr is required")
	}

	return &CustomClientTransport{
		config: cfg,
	}, nil
}

// Dial 实现 ClientTransport 接口
func (cct *CustomClientTransport) Dial(ctx context.Context) (net.Conn, error) {
	// TODO: 实现自定义连接建立逻辑
	return nil, fmt.Errorf("not implemented")
}

// Close 实现 ClientTransport 接口
func (cct *CustomClientTransport) Close() error {
	// TODO: 实现清理逻辑
	return nil
}

// CustomTransportFactory 工厂实现示例
type customTransportFactory struct{}

func (f *customTransportFactory) CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error) {
	return NewCustomServerTransport(cfg)
}

func (f *customTransportFactory) CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error) {
	return NewCustomClientTransport(cfg)
}

// 使用示例：如何在程序中注册自定义传输
/*
func main() {
	tm := GetTransportManager()
	
	// 注册自定义传输
	customType := TransportType("custom")
	tm.RegisterServerTransport(customType, &customTransportFactory{})
	tm.RegisterClientTransport(customType, &customTransportFactory{})
	
	// 现在就可以在配置中使用 transport: "custom"
	cfg := TransportServerConfig{
		Type:       customType,
		ListenAddr: ":8000",
		// ... 其他配置
	}
	
	transport, err := tm.CreateServerTransport(cfg)
	// ...
}
*/
