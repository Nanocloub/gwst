package main

import (
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zijiren233/gwst/compat"
	"github.com/zijiren233/gwst/internal/config"
	"github.com/zijiren233/gwst/internal/crypto"
	"github.com/zijiren233/gwst/internal/utils"
)

func init() {
	initLogger()
}

func initLogger() {
	log.SetOutput(os.Stdout)
	log.SetReportCaller(false)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:      true,
		DisableColors:    false,
		DisableQuote:     true,
		DisableSorting:   false,
		FullTimestamp:    true,
		TimestampFormat:  time.DateTime,
		QuoteEmptyFields: true,
	})
	stdlog.SetOutput(log.StandardLogger().Writer())
}

func main() {
	if len(os.Args) < 2 {
		log.Error("Usage: gwst <config.yaml>")
		os.Exit(1)
	}

	configFile := os.Args[1]

	endpoints, err := config.LoadFromFile(configFile)
	if err != nil {
		log.Errorf("Failed to load config: %v", err)
		os.Exit(1)
	}

	log.Infof("Loaded %d endpoint(s)", len(endpoints))

	for _, endpoint := range endpoints {
		if err := endpoint.Validate(); err != nil {
			log.Errorf("Invalid endpoint config: %v", err)
			os.Exit(1)
		}

		printEndpointInfo(endpoint)

		go run(endpoint)
	}

	log.Info("All endpoints started, press Ctrl+C to stop")

	select {}
}

func run(endpoint config.Endpoint) {
	for {
		var s server

		if endpoint.IsClient {
			s = newClient(endpoint)
		} else {
			s = newServer(endpoint)
		}
		// 使用匿名函数确保Close在每次迭代结束时执行
		func() {
			defer func() {
				if err := s.Close(); err != nil {
					log.Errorf("Error closing %s: %v", endpoint.ListenAddr, err)
				}
			}()

			err := s.Serve()
			if err != nil {
				log.Errorf("Error serving %s: %v", endpoint.ListenAddr, err)
				log.Warnf("Restarting %s in 3 seconds...", endpoint.ListenAddr)
				time.Sleep(time.Second * 3)
			}
		}()
	}
}

type server interface {
	Serve() error
	Close() error
}

func printEndpointInfo(ep config.Endpoint) {
	log.Info("----------------------------------------")

	if ep.IsClient {
		printClientEndpointInfo(ep)
	} else {
		printServerEndpointInfo(ep)
	}

	log.Info("----------------------------------------")
}

func printClientEndpointInfo(ep config.Endpoint) {
	transportInfo := fmt.Sprintf("Transport: %s", ep.GetTransportType())

	if ep.Target == "" && ep.NamedTarget == "" {
		log.Infof("Starting client on %s -> %s (%s)", ep.ListenAddr, ep.TargetAddr, transportInfo)
	} else if ep.NamedTarget != "" {
		log.Infof("Starting client on %s -> %s (Named: %s, %s)", ep.ListenAddr, ep.TargetAddr, ep.NamedTarget, transportInfo)
	} else {
		log.Infof("Starting client on %s -> %s (Target: %s, %s)", ep.ListenAddr, ep.TargetAddr, ep.Target, transportInfo)
	}
}

func printServerEndpointInfo(ep config.Endpoint) {
	transportInfo := fmt.Sprintf("Transport: %s", ep.GetTransportType())

	if len(ep.AllowedTargets) != 0 || len(ep.NamedTargets) != 0 {
		if ep.TargetAddr == "" {
			log.Infof("Starting server on %s (%s)", ep.ListenAddr, transportInfo)

			if len(ep.AllowedTargets) != 0 {
				log.Warnf("\tAllowed targets: %v", ep.AllowedTargets)
			}

			if len(ep.NamedTargets) != 0 {
				log.Warn("\tNamed targets:")

				for name, target := range ep.NamedTargets {
					log.Infof("\t\t%s -> %s", name, target.Addr)
				}
			}
		} else {
			log.Infof("Starting server on %s -> %s (%s)", ep.ListenAddr, ep.TargetAddr, transportInfo)

			if len(ep.AllowedTargets) != 0 {
				log.Warnf("\tAdditional allowed targets: %v", ep.AllowedTargets)
			}

			if len(ep.NamedTargets) != 0 {
				log.Warn("\tNamed targets:")

				for name, target := range ep.NamedTargets {
					log.Infof("\t\t%s -> %s", name, target.Addr)
				}
			}
		}
	} else {
		log.Infof("Starting server on %s -> %s (%s)", ep.ListenAddr, ep.TargetAddr, transportInfo)
	}
}

func newServer(endpoint config.Endpoint) *compat.Server {
	// 转换 transport.NamedTarget 到 tunnel.NamedTarget
	namedTargets := make(map[string]compat.NamedTarget, len(endpoint.NamedTargets))
	for name, target := range endpoint.NamedTargets {
		namedTargets[name] = compat.NamedTarget{
			Addr:          target.Addr,
			FallbackAddrs: target.FallbackAddrs,
		}
	}

	// key 仅用于认证 (X-Key header)，encryption_key 独立用于数据加密
	handlerOpts := []compat.HandlerOption{
		compat.WithHandlerLogger(log.StandardLogger()),
		compat.WithHandlerDefaultTargetAddr(endpoint.TargetAddr),
		compat.WithHandlerAllowedTargets(endpoint.AllowedTargets),
		compat.WithHandlerNamedTargets(namedTargets),
		compat.WithHandlerFallbackAddrs(endpoint.FallbackAddrs),
		compat.WithHandlerLoadBalance(endpoint.LoadBalance),
		compat.WithHandlerKey(endpoint.Key),
	}

	// encryption_key 独立处理数据加密
	if endpoint.EncryptionKey != "" {
		if len(endpoint.EncryptionKey) < crypto.KeySize {
			log.Errorf("encryption_key length (%d) < %d bytes, encryption disabled", len(endpoint.EncryptionKey), crypto.KeySize)
		} else {
			algo := crypto.Algorithm(endpoint.EncryptionAlgo)
			cryptoManager, err := crypto.NewManagerWithAlgo([]byte(endpoint.EncryptionKey[:crypto.KeySize]), algo)
			if err != nil {
				log.Warnf("Failed to create crypto manager: %v, encryption disabled", err)
			} else {
				handlerOpts = append(handlerOpts, compat.WithHandlerCryptoManager(cryptoManager))
				log.Infof("%s encryption enabled for server on %s", cryptoManager.Algo(), endpoint.ListenAddr)
			}
		}
	}

	handler := compat.NewHandler(handlerOpts...)

	opts := []compat.ServerOption{
		compat.WithListenAddr(endpoint.ListenAddr),
		compat.WithTransport(endpoint.GetTransportType()),
	}
	if endpoint.TLS {
		opts = append(opts,
			compat.WithTLS(endpoint.CertFile, endpoint.KeyFile),
			compat.WithServerName(endpoint.ServerName),
		)
	}
	if endpoint.QUICInitialStreamReceiveWindow != 0 ||
		endpoint.QUICMaxStreamReceiveWindow != 0 ||
		endpoint.QUICInitialConnReceiveWindow != 0 ||
		endpoint.QUICMaxConnReceiveWindow != 0 {
		opts = append(opts, compat.WithQUICWindowSizes(
			endpoint.QUICInitialStreamReceiveWindow,
			endpoint.QUICMaxStreamReceiveWindow,
			endpoint.QUICInitialConnReceiveWindow,
			endpoint.QUICMaxConnReceiveWindow,
		))
	}
	if endpoint.QUICMaxIdleTimeout != 0 {
		opts = append(opts, compat.WithQUICMaxIdleTimeout(endpoint.QUICMaxIdleTimeout))
	}
	if endpoint.QUICMaxIncomingStreams != 0 {
		opts = append(opts, compat.WithQUICMaxIncomingStreams(endpoint.QUICMaxIncomingStreams))
	}
	if endpoint.QUICDisablePathMTUDiscovery {
		opts = append(opts, compat.WithQUICDisablePathMTUDiscovery(true))
	}

	return compat.NewServer(endpoint.Path, handler, opts...)
}

func newClient(endpoint config.Endpoint) *compat.Forwarder {
	opts := []compat.ConnectOption{
		compat.WithAddr(endpoint.TargetAddr),
		compat.WithPath(endpoint.Path),
		compat.WithHost(endpoint.Host),
		compat.WithTarget(endpoint.Target),
		compat.WithNamedTarget(endpoint.NamedTarget),
		compat.WithFallbackAddrs(endpoint.FallbackAddrs),
		compat.WithLoadBalance(endpoint.LoadBalance),
		compat.WithDialTLS(endpoint.TLS),
		compat.WithDialServerName(endpoint.ServerName),
		compat.WithInsecure(endpoint.Insecure),
		compat.WithCACertFile(endpoint.CACertFile),
		compat.WithKey(endpoint.Key),
		compat.WithTransportType(endpoint.GetTransportType()),
	}
	if endpoint.QUICInitialStreamReceiveWindow != 0 ||
		endpoint.QUICMaxStreamReceiveWindow != 0 ||
		endpoint.QUICInitialConnReceiveWindow != 0 ||
		endpoint.QUICMaxConnReceiveWindow != 0 {
		opts = append(opts, compat.WithDialQUICWindowSizes(
			endpoint.QUICInitialStreamReceiveWindow,
			endpoint.QUICMaxStreamReceiveWindow,
			endpoint.QUICInitialConnReceiveWindow,
			endpoint.QUICMaxConnReceiveWindow,
		))
	}
	if endpoint.QUICMaxIdleTimeout != 0 {
		opts = append(opts, compat.WithDialQUICMaxIdleTimeout(endpoint.QUICMaxIdleTimeout))
	}
	if endpoint.QUICDisablePathMTUDiscovery {
		opts = append(opts, compat.WithDialQUICDisablePathMTUDiscovery(true))
	}

	forwarderOpts := []compat.ForwarderOption{
		compat.WithLogger(log.StandardLogger()),
	}

	// encryption_key 独立处理数据加密（通过 ConnectOption 下发到 Dialer）
	if endpoint.EncryptionKey != "" {
		if len(endpoint.EncryptionKey) < crypto.KeySize {
			log.Errorf("encryption_key length (%d) < %d bytes, encryption disabled", len(endpoint.EncryptionKey), crypto.KeySize)
		} else {
			algo := crypto.Algorithm(endpoint.EncryptionAlgo)
			opts = append(opts, compat.WithEncryptionKeyAndAlgo(endpoint.EncryptionKey, algo))
			if algo == "" {
				algo = crypto.AlgoAEGIS128L
			}
			log.Infof("%s encryption enabled for client on %s", algo, endpoint.ListenAddr)
		}
	}

	if endpoint.DisableTCP {
		forwarderOpts = append(forwarderOpts, compat.WithDisableTCP())
	}

	if endpoint.DisableUDP {
		forwarderOpts = append(forwarderOpts, compat.WithDisableUDP())
	}

	if endpoint.DisableUDPEarlyData {
		forwarderOpts = append(forwarderOpts, compat.WithDisableUDPEarlyData())
	}

	wsDialer := compat.NewDialer(opts...)

	// Create a dialer adapter to wrap compat.Dialer for use with Forwarder
	dialerAdapter := &dialerAdapter{wsDialer: wsDialer}

	return compat.NewForwarder(
		endpoint.ListenAddr,
		dialerAdapter,
		forwarderOpts...,
	)
}

// dialerAdapter wraps ws.Dialer to implement dialer.WebSocketDialer interface
type dialerAdapter struct {
	wsDialer *compat.Dialer
}

func (da *dialerAdapter) DialTCP() (io.ReadWriteCloser, error) {
	return da.wsDialer.DialTCP()
}

func (da *dialerAdapter) DialUDP() (io.ReadWriteCloser, error) {
	return da.wsDialer.DialUDP()
}

func (da *dialerAdapter) DialUDPWithHeaders(headers http.Header) (io.ReadWriteCloser, error) {
	return da.wsDialer.DialUDP(compat.WithAppendHeaders(headers))
}

func (da *dialerAdapter) CryptoManager() utils.CryptoManager {
	return da.wsDialer.CryptoManager()
}
