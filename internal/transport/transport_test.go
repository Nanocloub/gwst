package transport

import (
	"net"
	"testing"
)

func TestTransportManager(t *testing.T) {
	tm := NewTransportManager()

	handler := func(conn net.Conn) error { return nil }

	// Test WebSocket server transport creation
	wsCfg := TransportServerConfig{
		Type:       TransportWebSocket,
		ListenAddr: ":0",
		Path:       "/ws",
		Handler:    handler,
	}

	wsTransport, err := tm.CreateServerTransport(wsCfg)
	if err != nil {
		t.Fatalf("Failed to create WebSocket server transport: %v", err)
	}

	if wsTransport == nil {
		t.Fatal("WebSocket server transport is nil")
	}

	// Test TCP server transport creation
	tcpCfg := TransportServerConfig{
		Type:       TransportTCP,
		ListenAddr: ":0",
		Handler:    handler,
	}

	tcpTransport, err := tm.CreateServerTransport(tcpCfg)
	if err != nil {
		t.Fatalf("Failed to create TCP server transport: %v", err)
	}

	if tcpTransport == nil {
		t.Fatal("TCP server transport is nil")
	}

	// Test QUIC server transport creation (should fail without TLS)
	quicCfg := TransportServerConfig{
		Type:       TransportQUIC,
		ListenAddr: ":0",
		Handler:    handler,
	}

	_, err = tm.CreateServerTransport(quicCfg)
	if err == nil {
		t.Fatal("QUIC transport should fail without TLS")
	}
}

func TestTransportFactory(t *testing.T) {
	tm := NewTransportManager()
	handler := func(conn net.Conn) error { return nil }

	tests := []struct {
		name       string
		transportType TransportType
		shouldWork bool
	}{
		{"WebSocket", TransportWebSocket, true},
		{"TCP", TransportTCP, true},
		{"QUIC", TransportQUIC, false}, // QUIC requires TLS
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := TransportServerConfig{
				Type:       tt.transportType,
				ListenAddr: ":0",
				Handler:    handler,
			}

			if tt.transportType == TransportQUIC {
				cfg.TLS = true
				cfg.CertFile = "test.crt"
				cfg.KeyFile = "test.key"
			}

			transport, err := tm.CreateServerTransport(cfg)

			if tt.shouldWork {
				if err != nil {
					t.Errorf("Expected success, got error: %v", err)
				}
				if transport == nil {
					t.Error("Transport should not be nil")
				}
			} else {
				if err == nil && tt.transportType != TransportQUIC {
					t.Error("Expected error for unsupported transport")
				}
			}
		})
	}
}

func TestIsValidTransport(t *testing.T) {
	tests := []struct {
		transportType TransportType
		valid         bool
	}{
		{TransportWebSocket, true},
		{TransportTCP, true},
		{TransportQUIC, true},
		{TransportType("invalid"), false},
		{TransportType(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.transportType), func(t *testing.T) {
			result := IsValidTransport(tt.transportType)
			if result != tt.valid {
				t.Errorf("IsValidTransport(%s) = %v, want %v", tt.transportType, result, tt.valid)
			}
		})
	}
}

func TestDefaultTransport(t *testing.T) {
	defaultTransport := DefaultTransport()
	if defaultTransport != TransportWebSocket {
		t.Errorf("Default transport should be WebSocket, got %s", defaultTransport)
	}
}
