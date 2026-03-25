package compat

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/zijiren233/gwst/internal/crypto"
	"github.com/zijiren233/gwst/internal/transport"
	"github.com/zijiren233/gwst/internal/utils"
	"golang.org/x/net/websocket"
)

var randomFingerprint tls.ClientHelloID

func init() {
	modernFingerprints := []tls.ClientHelloID{
		tls.HelloChrome_Auto,
		tls.HelloFirefox_Auto,
		tls.HelloEdge_Auto,
		tls.HelloSafari_Auto,
		tls.HelloIOS_Auto,
	}
	randomFingerprint = modernFingerprints[rand.IntN(len(modernFingerprints))]
}

var defaultDialer = &net.Dialer{
	Timeout: time.Second * 5,
}

type ConnectAddrConfig struct {
	Addr          string
	FallbackAddrs []string
}

func (c *ConnectAddrConfig) Clone() *ConnectAddrConfig {
	return &ConnectAddrConfig{
		Addr:          c.Addr,
		FallbackAddrs: slices.Clone(c.FallbackAddrs),
	}
}

type ConnectDialConfig struct {
	Dialer        *net.Dialer
	ListenConfig  *net.ListenConfig
	Headers       http.Header
	Host          string
	Path          string
	Target        string
	NamedTarget   string
	ServerName    string
	Key           string
	TLS           bool
	Insecure      bool
	UDP           bool
	LoadBalance   bool
	TransportType string // \"websocket\", \"tcp\", or \"quic\"
	// 可选的加密管理器（当配置了 encryption_key 时自动创建）
	CryptoManager utils.CryptoManager
	// QUIC 接收窗口大小（字节），0 表示使用 quic-go 默认值
	QUICInitialStreamReceiveWindow uint64
	QUICMaxStreamReceiveWindow     uint64
	QUICInitialConnReceiveWindow   uint64
	QUICMaxConnReceiveWindow       uint64
}

type splitedConnectDialConfig struct {
	*ConnectDialConfig
	splitAddr string
	splitPort string
}

func (c *ConnectDialConfig) Clone() *ConnectDialConfig {
	clone := *c
	clone.Headers = clone.Headers.Clone()
	return &clone
}

type ConnectConfig struct {
	ConnectAddrConfig
	ConnectDialConfig
}

func (c *ConnectConfig) Clone() *ConnectConfig {
	return &ConnectConfig{
		ConnectAddrConfig: *c.ConnectAddrConfig.Clone(),
		ConnectDialConfig: *c.ConnectDialConfig.Clone(),
	}
}

type ConnectOption func(*ConnectConfig)

func WithURL(u *url.URL) ConnectOption {
	return func(c *ConnectConfig) {
		c.Addr = u.Host

		c.Path = u.Path
		switch u.Scheme {
		case "wss", "https":
			c.TLS = true
		default:
			c.TLS = false
		}
	}
}

func WithAddr(addr string) ConnectOption {
	return func(c *ConnectConfig) {
		c.Addr = addr
	}
}

func WithFallbackAddrs(addrs []string) ConnectOption {
	return func(c *ConnectConfig) {
		c.FallbackAddrs = addrs
	}
}

func WithHost(host string) ConnectOption {
	return func(c *ConnectConfig) {
		c.Host = host
	}
}

func WithPath(path string) ConnectOption {
	return func(c *ConnectConfig) {
		c.Path = path
	}
}

func WithTarget(target string) ConnectOption {
	return func(c *ConnectConfig) {
		c.Target = target
	}
}

func WithNamedTarget(namedTarget string) ConnectOption {
	return func(c *ConnectConfig) {
		c.NamedTarget = namedTarget
	}
}

func WithDialTLS(tls bool) ConnectOption {
	return func(c *ConnectConfig) {
		c.TLS = tls
	}
}

func WithDialServerName(serverName string) ConnectOption {
	return func(c *ConnectConfig) {
		c.ServerName = serverName
	}
}

func WithInsecure(insecure bool) ConnectOption {
	return func(c *ConnectConfig) {
		c.Insecure = insecure
	}
}

func WithUDP() ConnectOption {
	return func(c *ConnectConfig) {
		c.UDP = true
	}
}

func WithDialer(dialer *net.Dialer) ConnectOption {
	return func(c *ConnectConfig) {
		c.Dialer = dialer
	}
}

func WithLoadBalance(loadBalance bool) ConnectOption {
	return func(c *ConnectConfig) {
		c.LoadBalance = loadBalance
	}
}

func WithAppendHeaders(headers http.Header) ConnectOption {
	return func(c *ConnectConfig) {
		if c.Headers == nil {
			c.Headers = headers
		} else {
			maps.Copy(c.Headers, headers)
		}
	}
}

func WithHeaders(headers http.Header) ConnectOption {
	return func(c *ConnectConfig) {
		c.Headers = headers
	}
}

// WithEncryptionKey 在连接配置中启用加密（使用 AEGIS-128L）
// key 需至少 16 字节，仅取前 16 字节作为密钥
func WithEncryptionKey(key string) ConnectOption {
	return func(c *ConnectConfig) {
		if len(key) < crypto.KeySize {
			// 无效密钥长度：忽略加密设置
			return
		}
		cm, err := crypto.NewManager([]byte(key[:crypto.KeySize]))
		if err != nil {
			return
		}
		c.CryptoManager = cm
	}
}

func WithKey(key string) ConnectOption {
	return func(c *ConnectConfig) {
		c.Key = key
	}
}

// WithListenConfig sets a custom net.ListenConfig (used for QUIC/UDP Android VPN socket protection)
func WithListenConfig(lc *net.ListenConfig) ConnectOption {
	return func(c *ConnectConfig) {
		c.ListenConfig = lc
	}
}

func WithTransportType(transportType string) ConnectOption {
	return func(c *ConnectConfig) {
		c.TransportType = transportType
	}
}

// WithDialQUICWindowSizes 设置 QUIC 接收窗口大小。
// initialStream/maxStream 控制每条流的接收窗口，initialConn/maxConn 控制整个连接的接收窗口。
// 0 表示保持 quic-go 默认值（stream: 512KB/6MB，conn: 512KB/15MB）。
func WithDialQUICWindowSizes(initialStream, maxStream, initialConn, maxConn uint64) ConnectOption {
	return func(c *ConnectConfig) {
		c.QUICInitialStreamReceiveWindow = initialStream
		c.QUICMaxStreamReceiveWindow = maxStream
		c.QUICInitialConnReceiveWindow = initialConn
		c.QUICMaxConnReceiveWindow = maxConn
	}
}

func Connect(ctx context.Context, opts ...ConnectOption) (net.Conn, error) {
	cfg := ConnectConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	return ConnectWithConfig(ctx, cfg)
}

func ConnectWithConfig(ctx context.Context, cfg ConnectConfig) (net.Conn, error) {
	if cfg.TransportType == "" {
		cfg.TransportType = "websocket"
	}

	if cfg.TransportType == "tcp" || cfg.TransportType == "quic" {
		return connectWithTransport(ctx, cfg)
	}

	if cfg.Addr == "" && len(cfg.FallbackAddrs) > 0 {
		cfg.Addr = cfg.FallbackAddrs[0]
		cfg.FallbackAddrs = cfg.FallbackAddrs[1:]
	}

	dialCfg, err := generateDialConfig(cfg.Addr, cfg.ConnectDialConfig)
	if err != nil {
		return nil, err
	}

	if cfg.LoadBalance {
		cfg.Addr, cfg.FallbackAddrs = balanceTargets(cfg.Addr, cfg.FallbackAddrs)
	}

	ws, err := connect(ctx, dialCfg)
	if err == nil {
		ws.PayloadType = websocket.BinaryFrame
		return utils.NewCryptoConn(ws, cfg.CryptoManager, false), nil
	}

	if len(cfg.FallbackAddrs) == 0 {
		return nil, fmt.Errorf("failed to connect to %s, error: %w", cfg.Addr, err)
	}

	var errs []error
	for i := 0; i < len(cfg.FallbackAddrs); i += 3 {
		end := min(i+3, len(cfg.FallbackAddrs))

		batch := cfg.FallbackAddrs[i:end]

		ws, cerr := connectConcurrent(ctx, dialCfg, batch)
		if cerr == nil {
			ws.PayloadType = websocket.BinaryFrame
			return utils.NewCryptoConn(ws, cfg.CryptoManager, false), nil
		}

		errs = append(errs, cerr)
	}

	return nil, errors.Join(errs...)
}

func connectConcurrent(
	ctx context.Context,
	cfg *splitedConnectDialConfig,
	addrs []string,
) (*websocket.Conn, error) {
	type result struct {
		conn *websocket.Conn
		err  error
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan result, len(addrs))

	var wg sync.WaitGroup

	for _, addr := range addrs {
		wg.Add(1)

		go func(addr string) {
			defer wg.Done()

			dialCfgCopy, err := generateDialConfig(addr, *cfg.ConnectDialConfig)
			if err != nil {
				results <- result{nil, err}
				return
			}

			conn, err := connect(ctx, dialCfgCopy)
			results <- result{conn, err}
		}(addr)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Cleanup goroutine to close unused connections after context cancellation
	go func() {
		<-ctx.Done()
		for res := range results {
			if res.conn != nil {
				res.conn.Close()
			}
		}
	}()

	errs := make([]error, 0, len(addrs))
	for res := range results {
		if res.err == nil {
			return res.conn, nil
		}

		errs = append(errs, res.err)
	}

	return nil, errors.Join(errs...)
}

func generateDialConfig(addr string, cfg ConnectDialConfig) (*splitedConnectDialConfig, error) {
	if cfg.Dialer == nil {
		cfg.Dialer = defaultDialer
	}

	addr, port, err := parseAddrAndPort(addr, cfg.TLS)
	if err != nil {
		return nil, err
	}

	splitCfg := splitedConnectDialConfig{
		splitAddr:         addr,
		splitPort:         port,
		ConnectDialConfig: &cfg,
	}

	if cfg.Host == "" {
		if cfg.ServerName != "" {
			cfg.Host = cfg.ServerName
		} else {
			cfg.Host = addr
		}
	}

	if cfg.ServerName == "" {
		cfg.ServerName = cfg.Host
	}

	cfg.Path = ensureLeadingSlash(cfg.Path)

	return &splitCfg, nil
}

func parseAddrAndPort(addr string, tlsEnabled bool) (string, string, error) {
	domain, port, err := net.SplitHostPort(addr)
	if err != nil {
		if strings.Contains(err.Error(), "missing port in address") {
			return addr, defaultPort(tlsEnabled), nil
		}
		return "", "", fmt.Errorf("failed to split host and port: %w", err)
	}

	return domain, port, nil
}

func defaultPort(tlsEnabled bool) string {
	if tlsEnabled {
		return "443"
	}
	return "80"
}

func ensureLeadingSlash(path string) string {
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func connect(ctx context.Context, cfg *splitedConnectDialConfig) (*websocket.Conn, error) {
	wsConfig, err := createWebsocketConfig(cfg.ConnectDialConfig)
	if err != nil {
		return nil, err
	}

	dialConn, err := dialWithTimeout(ctx, cfg.Dialer, cfg.splitAddr, cfg.splitPort)
	if err != nil {
		return nil, err
	}

	if cfg.TLS {
		config := &tls.Config{
			InsecureSkipVerify: cfg.Insecure,
			ServerName:         cfg.ServerName,
			MinVersion:         tls.VersionTLS13,
		}

		var tlsConn *tls.UConn

		tlsConn, err = createTLSClient(dialConn, config)
		if err != nil {
			dialConn.Close()
			return nil, err
		}

		dialConn = tlsConn
	}

	ws, err := websocket.NewClient(wsConfig, dialConn)
	if err != nil {
		dialConn.Close()
		return nil, err
	}

	return ws, nil
}

func createWebsocketConfig(cfg *ConnectDialConfig) (*websocket.Config, error) {
	var server, origin string
	if cfg.TLS {
		server = fmt.Sprintf("wss://%s%s", cfg.Host, cfg.Path)
		origin = fmt.Sprintf("https://%s%s", cfg.Host, cfg.Path)
	} else {
		server = fmt.Sprintf("ws://%s%s", cfg.Host, cfg.Path)
		origin = fmt.Sprintf("http://%s%s", cfg.Host, cfg.Path)
	}

	wsConfig, err := websocket.NewConfig(server, origin)
	if err != nil {
		return nil, fmt.Errorf("failed to create websocket config: %w", err)
	}

	setReqHeader(wsConfig, cfg.UDP, cfg.Target, cfg.NamedTarget, cfg.Headers, cfg.Key)
	wsConfig.Dialer = cfg.Dialer

	return wsConfig, nil
}

func setReqHeader(
	wsConfig *websocket.Config,
	isUDP bool,
	target, namedTarget string,
	headers http.Header,
	key string,
) {
	wsConfig.Header.Set(
		"User-Agent",
		"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36",
	)

	if target != "" {
		wsConfig.Header.Set("X-Target", target)
	}

	if namedTarget != "" {
		wsConfig.Header.Set("X-Named-Target", namedTarget)
	}

	if isUDP {
		wsConfig.Header.Set("X-Protocol", "udp")
	}

	maps.Copy(wsConfig.Header, headers)

	if key != "" {
		wsConfig.Header.Set("X-Key", key)
	}
}

func dialWithTimeout(ctx context.Context, dialer *net.Dialer, addr, port string) (net.Conn, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	return dialer.DialContext(timeoutCtx, "tcp", fmt.Sprintf("%s:%s", addr, port))
}

func createTLSClient(conn net.Conn, config *tls.Config) (*tls.UConn, error) {
	client := tls.UClient(conn, config, tls.HelloCustom)

	spec, err := tls.UTLSIdToSpec(randomFingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get utls spec: %w", err)
	}

	hasALPNExtension := false
	for _, ext := range spec.Extensions {
		if alpnExt, ok := ext.(*tls.ALPNExtension); ok {
			alpnExt.AlpnProtocols = []string{"http/1.1"}
			hasALPNExtension = true
		}
	}

	if !hasALPNExtension {
		spec.Extensions = append(
			spec.Extensions,
			&tls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
		)
	}

	if err := client.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("failed to apply utls spec: %w", err)
	}

	return client, nil
}

type Dialer struct {
	config ConnectConfig
}

func NewDialer(options ...ConnectOption) *Dialer {
	wc := &Dialer{}
	for _, option := range options {
		option(&wc.config)
	}

	return wc
}

func (wc *Dialer) DialContext(
	ctx context.Context,
	network string,
	options ...ConnectOption,
) (net.Conn, error) {
	cfg := wc.config.Clone()

	cfg.UDP = strings.HasPrefix(network, "udp")
	for _, option := range options {
		option(cfg)
	}

	return ConnectWithConfig(ctx, *cfg)
}

func (wc *Dialer) Dial(network string, options ...ConnectOption) (net.Conn, error) {
	return wc.DialContext(context.Background(), network, options...)
}

func (wc *Dialer) DialUDP(options ...ConnectOption) (net.Conn, error) {
	return wc.Dial("udp", options...)
}

func (wc *Dialer) DialContextUDP(ctx context.Context, options ...ConnectOption) (net.Conn, error) {
	return wc.DialContext(ctx, "udp", options...)
}

func (wc *Dialer) DialTCP(options ...ConnectOption) (net.Conn, error) {
	return wc.Dial("tcp", options...)
}

func (wc *Dialer) DialContextTCP(ctx context.Context, options ...ConnectOption) (net.Conn, error) {
	return wc.DialContext(ctx, "tcp", options...)
}

// CryptoManager 返回在 ConnectOption 中配置的加密管理器（若未配置则为 nil）
func (wc *Dialer) CryptoManager() utils.CryptoManager {
	return wc.config.ConnectDialConfig.CryptoManager
}

// connectWithTransport 使用 transport 包进行连接（TCP 或 QUIC）
func connectWithTransport(ctx context.Context, cfg ConnectConfig) (net.Conn, error) {
	// 将 transport 字符串转换为 TransportType
	var transportType transport.TransportType
	switch cfg.TransportType {
	case "tcp":
		transportType = transport.TransportTCP
	case "quic":
		transportType = transport.TransportQUIC
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.TransportType)
	}

	// 创建传输配置
	transportCfg := transport.TransportClientConfig{
		Type:                           transportType,
		RemoteAddr:                     cfg.Addr,
		ServerName:                     cfg.ServerName,
		Insecure:                       cfg.Insecure,
		TLS:                            cfg.TLS,
		Context:                        ctx,
		Logger:                         transport.NewSafeLoggerOrNull(nil),
		Dialer:                         cfg.Dialer,
		ListenConfig:                   cfg.ListenConfig,
		QUICInitialStreamReceiveWindow: cfg.QUICInitialStreamReceiveWindow,
		QUICMaxStreamReceiveWindow:     cfg.QUICMaxStreamReceiveWindow,
		QUICInitialConnReceiveWindow:   cfg.QUICInitialConnReceiveWindow,
		QUICMaxConnReceiveWindow:       cfg.QUICMaxConnReceiveWindow,
	}

	// 复用全局传输管理器，避免每次拨号都重新分配 map 和工厂对象
	tm := transport.GetTransportManager()

	// 创建客户端传输
	clientTransport, err := tm.CreateClientTransport(transportCfg)
	if err != nil {
		return nil, err
	}

	// 拨号连接
	conn, err := clientTransport.Dial(ctx)
	if err != nil {
		return nil, err
	}

	// 发送协议标识字节
	// 0x01 = TCP, 0x02 = UDP
	protocolByte := byte(0x01)
	if cfg.UDP {
		protocolByte = 0x02
	}
	if _, err := conn.Write([]byte{protocolByte}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write protocol byte: %w", err)
	}

	// 使用 StreamKeepaliveConn 处理加密、帧封装和应用层心跳（Stream）
	return utils.NewStreamKeepaliveConn(conn, cfg.CryptoManager), nil
}
