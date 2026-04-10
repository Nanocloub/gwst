package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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
	// EncryptionAlgo 加密算法。不设置或留空则不启用加密（即使设置了 encryption_key 也不生效）。
	// 可选值："aegis-128l"（推荐）、"aegis-128x2"、"aegis-128x4"。
	// 客户端与服务端必须设置相同的值。
	EncryptionAlgo string `yaml:"encryption_algo"`

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
	// QUIC 连接最大空闲超时；0 = quic-go 内置默认（30s），两端协商取较小值
	QUICMaxIdleTimeout time.Duration `yaml:"quic_max_idle_timeout"`
	// QUIC 服务端允许对端打开的最大双向流数，0 表示使用 quic-go 默认值（100），仅服务端有效
	QUICMaxIncomingStreams int64 `yaml:"quic_max_incoming_streams"`
	// QUIC 初始包大小（字节），同时作为 BBR 拥塞控制的初始 datagram 大小。
	// 0 表示使用内部默认值（1452）。取值范围：[1200, 1452]。
	// 启用路径 MTU 探测时此为探测起点；禁用时则固定为此大小。
	QUICInitialPacketSize uint16 `yaml:"quic_initial_packet_size"`
	// 是否禁用 QUIC 路径 MTU 探测（RFC 8899），默认 false
	QUICDisablePathMTUDiscovery bool `yaml:"quic_disable_path_mtu_discovery"`

	// QUIC 拥塞控制类型。仅对 transport: quic 有效。
	// 可选值："bbr"（默认）、"reno"
	QUICCongestionType string `yaml:"quic_congestion_type"`
	// QUIC BBR 拥塞控制预设。仅当 quic_congestion_type 为 "bbr"（或默认）时有效。
	// 可选值："standard"（默认）、"conservative"、"aggressive"
	QUICBBRProfile string `yaml:"quic_bbr_profile"`
}

// Endpoints 表示配置文件中的所有端点
type Endpoints []Endpoint

// ExpandListenAddrs 解析 listenAddr，如果包含端口范围（如 ":8080-8090"），展开为独立地址列表。
// 若无端口范围，直接返回 []string{listenAddr}。
// 支持所有合法的 host:port 格式，包括 IPv6（如 "[::]:8080-8090"）。
func ExpandListenAddrs(listenAddr string) ([]string, error) {
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid listen_addr %q: %w", listenAddr, err)
	}

	dashIdx := strings.IndexByte(portStr, '-')
	if dashIdx < 0 {
		// 非端口范围，原样返回
		return []string{listenAddr}, nil
	}

	startStr := portStr[:dashIdx]
	endStr := portStr[dashIdx+1:]

	startPort, err := strconv.Atoi(startStr)
	if err != nil || startPort < 1 || startPort > 65535 {
		return nil, fmt.Errorf("invalid port range start %q in listen_addr %q", startStr, listenAddr)
	}
	endPort, err := strconv.Atoi(endStr)
	if err != nil || endPort < 1 || endPort > 65535 {
		return nil, fmt.Errorf("invalid port range end %q in listen_addr %q", endStr, listenAddr)
	}
	if startPort > endPort {
		return nil, fmt.Errorf("port range start %d > end %d in listen_addr %q", startPort, endPort, listenAddr)
	}

	addrs := make([]string, 0, endPort-startPort+1)
	for port := startPort; port <= endPort; port++ {
		addrs = append(addrs, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return addrs, nil
}

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

	// 验证端口范围语法（同时校验 host:port 格式）
	if _, err := ExpandListenAddrs(e.ListenAddr); err != nil {
		return err
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

	// 验证加密算法（空字符串表示默认 AEGIS-128L，合法）
	if e.EncryptionAlgo != "" {
		switch e.EncryptionAlgo {
		case "aegis-128l", "aegis-128x2", "aegis-128x4":
		default:
			return fmt.Errorf("invalid encryption_algo %q: must be aegis-128l, aegis-128x2, or aegis-128x4", e.EncryptionAlgo)
		}
	}

	// 验证 QUIC 拥塞控制配置
	switch e.QUICCongestionType {
	case "", "bbr", "reno":
	default:
		return fmt.Errorf("invalid quic_congestion_type %q: must be bbr or reno", e.QUICCongestionType)
	}
	switch e.QUICBBRProfile {
	case "", "standard", "conservative", "aggressive":
	default:
		return fmt.Errorf("invalid quic_bbr_profile %q: must be standard, conservative, or aggressive", e.QUICBBRProfile)
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
