package transport

import (
	"context"
	"net"
	"net/http"

	"github.com/zijiren233/gwst/internal/config"
	"github.com/zijiren233/gwst/internal/utils"
)

// Logger 日志接口，重新导出 utils.Logger
type Logger = utils.Logger

// CryptoManager 定义加密/解密操作接口，重新导出 utils.CryptoManager
type CryptoManager = utils.CryptoManager

// DeadlineWriter 接口用于支持写入期限的 io.Writer，重新导出 utils.DeadlineWriter
type DeadlineWriter = utils.DeadlineWriter

// NewSafeLoggerOrNull 创建一个安全的 logger，委托给 utils 实现
func NewSafeLoggerOrNull(logger Logger) Logger {
	return utils.NewSafeLoggerOrNull(logger)
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

// TransportType 定义传输层类型，重新导出 config.TransportType
type TransportType = config.TransportType

const (
	// TransportWebSocket WebSocket 传输
	TransportWebSocket = config.TransportWebSocket
	// TransportTCP 直接 TCP 传输
	TransportTCP = config.TransportTCP
	// TransportQUIC QUIC 传输
	TransportQUIC = config.TransportQUIC
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

// IsValidTransport 检查传输类型是否有效，委托给 config 实现
func IsValidTransport(t TransportType) bool {
	return config.IsValidTransport(t)
}

// DefaultTransport 返回默认的传输类型，委托给 config 实现
func DefaultTransport() TransportType {
	return config.DefaultTransport()
}

// IsValidTransportString 检查传输类型字符串是否有效，委托给 config 实现
func IsValidTransportString(s string) bool {
	return config.IsValidTransportString(s)
}

// NamedTarget 命名的目标地址配置，重新导出 config.NamedTarget
type NamedTarget = config.NamedTarget
