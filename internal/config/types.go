package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// NamedTarget 命名的目标地址配置
type NamedTarget struct {
	// 主地址
	Addr string `yaml:"addr"`

	// 回退地址列表
	FallbackAddrs []string `yaml:"fallback_addrs"`
}

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

// transportRegistry 传输注册表
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

// Endpoint 表示一个隧道端点配置
type Endpoint struct {
	// 基本配置
	IsClient   bool   `yaml:"is_client"`
	ListenAddr string `yaml:"listen_addr"`
	TargetAddr string `yaml:"target_addr"`

	// 负载均衡
	LoadBalance   bool     `yaml:"load_balance"`
	FallbackAddrs []string `yaml:"fallback_addrs"`

	// 目标地址管理
	AllowedTargets map[string][]string    `yaml:"allowed_targets"`
	NamedTargets   map[string]NamedTarget `yaml:"named_targets"`

	// 客户端目标选择
	Target      string `yaml:"target"`
	NamedTarget string `yaml:"named_target"`

	// 协议和路径
	Path      string `yaml:"path"`
	Host      string `yaml:"host"`
	Transport string `yaml:"transport"`

	// 认证和加密
	Key           string `yaml:"key"`            // 认证密钥(X-Key)，如果encryption_key未设置也用于加密
	EncryptionKey string `yaml:"encryption_key"` // 独立的加密密钥(推荐)，优先级高于key

	// TLS 配置
	TLS        bool   `yaml:"tls"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
	Insecure   bool   `yaml:"insecure"`
	// CACertFile 客户端信任的 CA 证书（PEM 格式，可直接填服务端自签证书）。
	// 设置后无需 insecure: true 即可验证自签证书。
	CACertFile string `yaml:"ca_cert_file"`

	// 协议开关
	DisableTCP          bool `yaml:"disable_tcp"`
	DisableUDP          bool `yaml:"disable_udp"`
	DisableUDPEarlyData bool `yaml:"disable_udp_early_data"`

	// QUIC 流接收窗口大小（字节），0 表示使用 quic-go 默认值（512KB）
	QUICInitialStreamReceiveWindow uint64 `yaml:"quic_initial_stream_receive_window"`
	// QUIC 流最大接收窗口大小（字节），0 表示使用 quic-go 默认值（6MB）
	QUICMaxStreamReceiveWindow uint64 `yaml:"quic_max_stream_receive_window"`
	// QUIC 连接接收窗口大小（字节），0 表示使用 quic-go 默认值（512KB）
	QUICInitialConnReceiveWindow uint64 `yaml:"quic_initial_conn_receive_window"`
	// QUIC 连接最大接收窗口大小（字节），0 表示使用 quic-go 默认值（15MB）
	QUICMaxConnReceiveWindow uint64 `yaml:"quic_max_conn_receive_window"`
}

// Endpoints 表示配置文件中的所有端点
type Endpoints []Endpoint

// LoadFromFile 从 YAML 文件加载配置
func LoadFromFile(path string) (Endpoints, error) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var endpoints Endpoints
	err = yaml.Unmarshal(yamlFile, &endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no endpoints found in config file")
	}

	return endpoints, nil
}

// Validate 验证端点配置的有效性
func (e *Endpoint) Validate() error {
	if e.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}

	if e.IsClient {
		if e.TargetAddr == "" {
			return fmt.Errorf("target_addr is required for client")
		}
	} else {
		if e.TargetAddr == "" && len(e.NamedTargets) == 0 {
			return fmt.Errorf("target_addr or named_targets is required for server")
		}
	}

	// 验证传输类型
	if e.Transport != "" && !IsValidTransportString(e.Transport) {
		return fmt.Errorf("invalid transport type: %s", e.Transport)
	}

	// 验证 QUIC 传输必须启用 TLS
	transportType := e.GetTransportType()
	if transportType == string(TransportQUIC) && !e.TLS {
		return fmt.Errorf("QUIC transport requires TLS to be enabled (set tls: true)")
	}

	// 验证 TLS 配置
	if e.TLS {
		if !e.IsClient && (e.CertFile == "" || e.KeyFile == "") {
			return fmt.Errorf("cert_file and key_file required for TLS server")
		}
	}

	return nil
}

// GetTransportType 获取传输类型，如果未指定则返回默认值
func (e *Endpoint) GetTransportType() string {
	if e.Transport == "" {
		return string(DefaultTransport())
	}
	return e.Transport
}
