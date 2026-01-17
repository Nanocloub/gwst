package transport

import (
	"context"
	"net"
	"net/http"
)

// Logger 日志接口
type Logger interface {
	Info(...any)
	Infof(string, ...any)
	Warn(...any)
	Warnf(string, ...any)
	Error(...any)
	Errorf(string, ...any)
}

// SafeLogger 安全日志包装
type SafeLogger struct {
	logger Logger
}

func newSafeLogger(logger Logger) *SafeLogger {
	return &SafeLogger{logger: logger}
}

func (sl *SafeLogger) Info(v ...any) {
	if sl.logger != nil {
		sl.logger.Info(v...)
	}
}

func (sl *SafeLogger) Infof(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Infof(format, v...)
	}
}

func (sl *SafeLogger) Warn(v ...any) {
	if sl.logger != nil {
		sl.logger.Warn(v...)
	}
}

func (sl *SafeLogger) Warnf(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Warnf(format, v...)
	}
}

func (sl *SafeLogger) Error(v ...any) {
	if sl.logger != nil {
		sl.logger.Error(v...)
	}
}

func (sl *SafeLogger) Errorf(format string, v ...any) {
	if sl.logger != nil {
		sl.logger.Errorf(format, v...)
	}
}

// 加密相关常量
const (
	// AegisKeySize AEGIS-128L 密钥大小
	AegisKeySize = 16
	// AegisNonceSize AEGIS-128L nonce 大小
	AegisNonceSize = 16
	// AegisTagSize AEGIS-128L tag 大小
	AegisTagSize = 16
)

// TransportType 定义传输层类型
type TransportType string

const (
	// TransportWebSocket WebSocket 传输
	TransportWebSocket TransportType = "websocket"
	// TransportTCP 直接 TCP 传输
	TransportTCP TransportType = "tcp"
	// TransportQUIC QUIC 传输
	TransportQUIC TransportType = "quic"
)

// ServerTransport 定义服务端传输接口
type ServerTransport interface {
	// Serve 启动服务并接受连接
	Serve() error
	
	// Close 关闭服务
	Close() error
	
	// WaitListen 等待服务启动
	WaitListen() error
	
	// WaitShutdown 等待服务关闭
	WaitShutdown() <-chan struct{}
}

// ClientTransport 定义客户端传输接口
type ClientTransport interface {
	// Dial 建立连接
	Dial(ctx context.Context) (net.Conn, error)
	
	// Close 关闭客户端
	Close() error
}

// ServerTransportFactory 服务端传输工厂接口
type ServerTransportFactory interface {
	// CreateServerTransport 创建服务端传输实例
	CreateServerTransport(cfg TransportServerConfig) (ServerTransport, error)
}

// ClientTransportFactory 客户端传输工厂接口
type ClientTransportFactory interface {
	// CreateClientTransport 创建客户端传输实例
	CreateClientTransport(cfg TransportClientConfig) (ClientTransport, error)
}

// TransportServerConfig 服务端传输配置
type TransportServerConfig struct {
	// 监听地址
	ListenAddr string
	
	// 传输类型
	Type TransportType
	
	// HTTP 路径（仅 WebSocket 需要）
	Path string
	
	// 认证密钥
	Key string
	
	// 是否启用 TLS
	TLS bool
	
	// TLS 证书文件
	CertFile string
	
	// TLS 密钥文件
	KeyFile string
	
	// 服务名称（TLS SNI）
	ServerName string
	
	// 处理连接的回调函数
	Handler func(net.Conn) error
	
	// 额外的 HTTP Header（WebSocket 需要）
	Headers http.Header
	
	// Logger 实例
	Logger Logger
}

// TransportClientConfig 客户端传输配置
type TransportClientConfig struct {
	// 远程地址
	RemoteAddr string
	
	// 传输类型
	Type TransportType
	
	// HTTP 主机名（WebSocket 需要）
	Host string
	
	// HTTP 路径（WebSocket 需要）
	Path string
	
	// 认证密钥
	Key string
	
	// 是否启用 TLS
	TLS bool
	
	// TLS 服务名称
	ServerName string
	
	// TLS 是否跳过验证
	Insecure bool
	
	// 额外的 HTTP Header（WebSocket 需要）
	Headers http.Header
	
	// Logger 实例
	Logger Logger
	
	// 上下文
	Context context.Context
}

// TransportRegistry 传输注册表
var transportRegistry = map[TransportType]struct{}{
	TransportWebSocket: {},
	TransportTCP:       {},
	TransportQUIC:      {},
}

// IsValidTransport 检查传输类型是否有效
func IsValidTransport(t TransportType) bool {
	_, ok := transportRegistry[t]
	return ok
}

// DefaultTransport 返回默认的传输类型
func DefaultTransport() TransportType {
	return TransportWebSocket
}

// IsValidTransportString 检查传输类型字符串是否有效
func IsValidTransportString(s string) bool {
	return IsValidTransport(TransportType(s))
}

// NamedTarget 命名的目标地址配置
type NamedTarget struct {
	// 主地址
	Addr string `yaml:"addr"`
	
	// 回退地址列表
	FallbackAddrs []string `yaml:"fallback_addrs"`
}

