package config

import (
	"fmt"
	"os"

	"github.com/zijiren233/gwst/internal/transport"
	"gopkg.in/yaml.v3"
)

// Endpoint 表示一个隧道端点配置
type Endpoint struct {
	// 基本配置
	IsClient bool   `yaml:"is_client"`
	ListenAddr string `yaml:"listen_addr"`
	TargetAddr string `yaml:"target_addr"`

	// 负载均衡
	LoadBalance bool     `yaml:"load_balance"`
	FallbackAddrs []string `yaml:"fallback_addrs"`

	// 目标地址管理
	AllowedTargets map[string][]string `yaml:"allowed_targets"`
	NamedTargets   map[string]transport.NamedTarget `yaml:"named_targets"`

	// 客户端目标选择
	Target     string `yaml:"target"`
	NamedTarget string `yaml:"named_target"`

	// 协议和路径
	Path      string `yaml:"path"`
	Host      string `yaml:"host"`
	Transport string `yaml:"transport"`

	// 加密
	Key string `yaml:"key"`

	// TLS 配置
	TLS        bool   `yaml:"tls"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	ServerName string `yaml:"server_name"`
	Insecure   bool   `yaml:"insecure"`

	// 协议开关
	DisableTCP          bool `yaml:"disable_tcp"`
	DisableUDP          bool `yaml:"disable_udp"`
	DisableUDPEarlyData bool `yaml:"disable_udp_early_data"`
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
	if e.Transport != "" && !transport.IsValidTransportString(e.Transport) {
		return fmt.Errorf("invalid transport type: %s", e.Transport)
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
		return string(transport.DefaultTransport())
	}
	return e.Transport
}
