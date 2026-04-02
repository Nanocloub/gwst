package main

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
)

// ─── TCP/QUIC fallback_addrs tests ──────────────────────────────────────────

// TestTCPFallbackAddrs verifies that when the primary address is unreachable,
// connectWithTransport automatically retries the fallback addresses and
// completes a successful echo roundtrip through the tunnel.
func TestTCPFallbackAddrs(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:47111"
		serverAddr = "127.0.0.1:47112"
		deadAddr   = "127.0.0.1:47113" // nothing listening here
		fwdAddr    = "127.0.0.1:47114"
		payload    = "fallback_addrs_test"
	)

	// Start bidirectional echo backend.
	defer startBidirEchoTCP(t, echoAddr)()

	// Start gwst TCP tunnel server.
	handler := compat.NewHandler(compat.WithHandlerDefaultTargetAddr(echoAddr))
	srv := compat.NewServer("", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("tcp"),
	)
	go srv.Serve() //nolint:errcheck
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("tcp server WaitListen: %v", err)
	}
	defer srv.Close()

	// Dialer: primary = dead address, fallback = real server.
	d := compat.NewDialer(
		compat.WithAddr(deadAddr),
		compat.WithFallbackAddrs([]string{serverAddr}),
		compat.WithTransportType("tcp"),
	)

	// dialerAdapter wraps the compat.Dialer.
	da := &dialerAdapter{wsDialer: d}

	fwd := compat.NewForwarder(fwdAddr, da, compat.WithDisableUDP())
	go fwd.Serve() //nolint:errcheck
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("forwarder ListenErr: %v", err)
	}
	defer fwd.Close()

	// Connect through the forwarder and echo.
	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestWebsocketFallbackAddrs verifies that the existing WebSocket fallback
// logic still works correctly – primary address refuses, fallback succeeds.
func TestWebsocketFallbackAddrs(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:47121"
		serverAddr = "127.0.0.1:47122"
		deadAddr   = "127.0.0.1:47123" // nothing listening here
		fwdAddr    = "127.0.0.1:47124"
		payload    = "ws_fallback_test"
	)

	defer startBidirEchoTCP(t, echoAddr)()

	handler := compat.NewHandler(compat.WithHandlerDefaultTargetAddr(echoAddr))
	srv := compat.NewServer("/ws", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("websocket"),
	)
	go srv.Serve() //nolint:errcheck
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("ws server WaitListen: %v", err)
	}
	defer srv.Close()

	d := compat.NewDialer(
		compat.WithAddr(deadAddr),
		compat.WithFallbackAddrs([]string{serverAddr}),
		compat.WithTransportType("websocket"),
		compat.WithPath("/ws"),
	)
	da := &dialerAdapter{wsDialer: d}

	fwd := compat.NewForwarder(fwdAddr, da, compat.WithDisableUDP())
	go fwd.Serve() //nolint:errcheck
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("forwarder ListenErr: %v", err)
	}
	defer fwd.Close()

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
}

// ─── IPv6 tunnel connectivity test ──────────────────────────────────────────

// TestIPv6TunnelWebSocket verifies that a WebSocket tunnel works end-to-end
// on an IPv6 loopback address.  The test is skipped on hosts where IPv6 is
// not available.
func TestIPv6TunnelWebSocket(t *testing.T) {
	if !ipv6Available() {
		t.Skip("IPv6 not available on this host")
	}

	const (
		echoAddr   = "[::1]:47131"
		serverAddr = "[::1]:47132"
		fwdAddr    = "127.0.0.1:47133"
		payload    = "ipv6_ws_test"
	)

	// Echo backend on IPv6.
	defer startBidirEchoTCP(t, echoAddr)()

	handler := compat.NewHandler(compat.WithHandlerDefaultTargetAddr(echoAddr))
	srv := compat.NewServer("/ws6", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("websocket"),
	)
	go srv.Serve() //nolint:errcheck
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("ipv6 ws server WaitListen: %v", err)
	}
	defer srv.Close()

	d := compat.NewDialer(
		compat.WithAddr(serverAddr), // [::1]:47132
		compat.WithPath("/ws6"),
		compat.WithTransportType("websocket"),
	)
	da := &dialerAdapter{wsDialer: d}

	fwd := compat.NewForwarder(fwdAddr, da, compat.WithDisableUDP())
	go fwd.Serve() //nolint:errcheck
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("forwarder ListenErr: %v", err)
	}
	defer fwd.Close()

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
}

// TestIPv6TunnelTCP verifies that a TCP-transport tunnel works over IPv6.
func TestIPv6TunnelTCP(t *testing.T) {
	if !ipv6Available() {
		t.Skip("IPv6 not available on this host")
	}

	const (
		echoAddr   = "[::1]:47141"
		serverAddr = "[::1]:47142"
		fwdAddr    = "127.0.0.1:47143"
		payload    = "ipv6_tcp_test"
	)

	defer startBidirEchoTCP(t, echoAddr)()

	handler := compat.NewHandler(compat.WithHandlerDefaultTargetAddr(echoAddr))
	srv := compat.NewServer("", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("tcp"),
	)
	go srv.Serve() //nolint:errcheck
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("ipv6 tcp server WaitListen: %v", err)
	}
	defer srv.Close()

	d := compat.NewDialer(
		compat.WithAddr(serverAddr),
		compat.WithTransportType("tcp"),
	)
	da := &dialerAdapter{wsDialer: d}

	fwd := compat.NewForwarder(fwdAddr, da, compat.WithDisableUDP())
	go fwd.Serve() //nolint:errcheck
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("forwarder ListenErr: %v", err)
	}
	defer fwd.Close()

	conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echo mismatch: got %q, want %q", got, payload)
	}
}

// ipv6Available returns true if a TCP connection to [::1] can be established.
// This is used to skip IPv6 tests on hosts without IPv6 support.
func ipv6Available() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	// Attempt to listen on IPv6 loopback; if it fails, IPv6 is not available.
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	ln.Close()
	return true
}
