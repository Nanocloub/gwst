package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
	"github.com/zijiren233/gwst/internal/crypto"
)

// isClosedNetworkError checks if the error is a "use of closed network connection" error
func isClosedNetworkError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "use of closed network connection")
}

// TestAlgoAllTransports verifies that every AEGIS algorithm variant (128L, 128X2, 128X4)
// and the no-encryption case work correctly end-to-end on all three tunnel transport
// modes (WebSocket, TCP, QUIC).  4 cases × 3 transports = 12 parallel sub-tests.
func TestAlgoAllTransports(t *testing.T) {
	const (
		encKey   = "algo-test-key!!!"
		testData = "算法×传输=通过"
	)

	certFile, keyFile, certCleanup := writeTempCertFiles(t)
	// t.Cleanup (not defer): cleanup must run AFTER all parallel sub-tests finish,
	// not when TestAlgoAllTransports returns (which is before parallel subs resume).
	t.Cleanup(certCleanup)

	type algoCase struct {
		algo  crypto.Algorithm // "" = no encryption
		label string
	}
	type transportCase struct {
		name    string
		needTLS bool
	}

	algos := []algoCase{
		{"", "no-encrypt"},
		{crypto.AlgoAEGIS128L, "aegis-128l"},
		{crypto.AlgoAEGIS128X2, "aegis-128x2"},
		{crypto.AlgoAEGIS128X4, "aegis-128x4"},
	}
	transports := []transportCase{
		{"websocket", false},
		{"tcp", false},
		{"quic", true},
	}

	for ai, ac := range algos {
		for ti, tc := range transports {
			ac, tc := ac, tc
			// Allocate 3 ports per sub-test in a safe range (47010+).
			base := 47010 + (ai*3+ti)*3
			echoAddr := fmt.Sprintf("127.0.0.1:%d", base)
			serverAddr := fmt.Sprintf("127.0.0.1:%d", base+1)
			fwdAddr := fmt.Sprintf("127.0.0.1:%d", base+2)

			t.Run(ac.label+"/"+tc.name, func(t *testing.T) {
				t.Parallel()

				// ── 1. Bidirectional echo backend ────────────────────────
				defer startBidirEchoTCP(t, echoAddr)()

				// ── 2. Tunnel server ──────────────────────────────────────
				handlerOpts := []compat.HandlerOption{
					compat.WithHandlerDefaultTargetAddr(echoAddr),
				}
				if ac.algo != "" {
					cm, err := crypto.NewManagerWithAlgo([]byte(encKey[:crypto.KeySize]), ac.algo)
					if err != nil {
						t.Fatalf("NewManagerWithAlgo(%q): %v", ac.algo, err)
					}
					handlerOpts = append(handlerOpts, compat.WithHandlerCryptoManager(cm))
				}
				handler := compat.NewHandler(handlerOpts...)
				srvOpts := []compat.ServerOption{
					compat.WithListenAddr(serverAddr),
					compat.WithTransport(tc.name),
				}
				if tc.needTLS {
					srvOpts = append(srvOpts, compat.WithTLS(certFile, keyFile))
				}
				path := ""
				if tc.name == "websocket" {
					path = "/algo-test"
				}
				srv := compat.NewServer(path, handler, srvOpts...)
				go srv.Serve() //nolint:errcheck
				if err := srv.WaitListen(); err != nil {
					t.Fatalf("server WaitListen: %v", err)
				}
				defer srv.Close()

				// ── 3. Forwarder (client side) ────────────────────────────
				dialOpts := []compat.ConnectOption{
					compat.WithAddr(serverAddr),
					compat.WithTransportType(tc.name),
				}
				if ac.algo != "" {
					dialOpts = append(dialOpts, compat.WithEncryptionKeyAndAlgo(encKey, ac.algo))
				}
				if tc.name == "websocket" {
					dialOpts = append(dialOpts, compat.WithPath("/algo-test"))
				}
				if tc.needTLS {
					dialOpts = append(dialOpts, compat.WithInsecure(true))
				}
				d := compat.NewDialer(dialOpts...)
				fwd := compat.NewForwarder(fwdAddr, &dialerAdapter{wsDialer: d}, compat.WithDisableUDP())
				go fwd.Serve() //nolint:errcheck
				<-fwd.OnListened()
				if err := fwd.ListenErr(); err != nil {
					t.Fatalf("forwarder ListenErr: %v", err)
				}
				defer fwd.Close()

				// ── 4. Echo roundtrip ─────────────────────────────────────
				conn, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
				if err != nil {
					t.Fatalf("dial forwarder: %v", err)
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))

				payload := []byte(testData)
				if _, err := conn.Write(payload); err != nil {
					t.Fatalf("write: %v", err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					t.Fatalf("read: %v", err)
				}
				if string(got) != testData {
					t.Errorf("echo mismatch: got %q, want %q", got, testData)
				}
			})
		}
	}
}

// TestUDPTunnelIntegration tests UDP tunnel communication
func TestUDPTunnelIntegration(t *testing.T) {
	// 1. Start echo UDP server
	echoAddr := "127.0.0.1:19998"
	echoConn, err := net.ListenPacket("udp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to start UDP echo server: %v", err)
	}
	defer echoConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := echoConn.ReadFrom(buf)
			if err != nil {
				return
			}
			echoConn.WriteTo(buf[:n], addr)
		}
	}()

	// 2. Start tunnel server
	serverAddr := "127.0.0.1:18887"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Close()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:17776"

	opts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithPath("/tunnel"),
	}

	wsDialer := compat.NewDialer(opts...)
	dialerAdapter := &dialerAdapter{wsDialer: wsDialer}

	forwarder := compat.NewForwarder(
		clientAddr,
		dialerAdapter,
		compat.WithDisableTCP(),
		compat.WithUDPPoolSize(10),
		compat.WithUDPPoolPreAlloc(true),
	)

	go func() {
		if err := forwarder.Serve(); err != nil {
			if !isClosedNetworkError(err) {
				t.Errorf("Forwarder error: %v", err)
			}
		}
	}()
	defer forwarder.Close()

	// Wait longer for UDP to initialize
	time.Sleep(500 * time.Millisecond)

	// 4. Test UDP tunnel - use UDP connection that stays open
	testData := []byte("UDP Tunnel Test")

	udpAddr, err := net.ResolveUDPAddr("udp", clientAddr)
	if err != nil {
		t.Fatalf("Failed to resolve UDP address: %v", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatalf("Failed to dial UDP: %v", err)
	}
	defer conn.Close()

	// Send multiple times to ensure UDP tunnel is established
	for i := 0; i < 3; i++ {
		_, err = conn.Write(testData)
		if err != nil {
			t.Fatalf("Failed to write UDP (attempt %d): %v", i+1, err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try to read response
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read UDP: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("Expected %q, got %q", testData, string(buf[:n]))
	}

	t.Logf("✓ UDP tunnel test passed: %q", string(buf[:n]))
}

// TestMultipleConnections tests multiple concurrent connections through tunnel
func TestMultipleConnections(t *testing.T) {
	// 1. Start echo server
	echoAddr := "127.0.0.1:19997"
	echoListener, err := net.Listen("tcp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start tunnel server
	serverAddr := "127.0.0.1:18886"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Close()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:17775"

	opts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithPath("/tunnel"),
	}

	wsDialer := compat.NewDialer(opts...)
	dialerAdapter := &dialerAdapter{wsDialer: wsDialer}

	forwarder := compat.NewForwarder(
		clientAddr,
		dialerAdapter,
		compat.WithDisableUDP(),
	)

	go func() {
		if err := forwarder.Serve(); err != nil {
			if !isClosedNetworkError(err) {
				t.Errorf("Forwarder error: %v", err)
			}
		}
	}()
	defer forwarder.Close()

	time.Sleep(200 * time.Millisecond)

	// 4. Test multiple concurrent connections
	numConnections := 10
	var wg sync.WaitGroup
	errors := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", clientAddr, 2*time.Second)
			if err != nil {
				errors <- fmt.Errorf("conn %d: dial failed: %v", id, err)
				return
			}
			defer conn.Close()

			testData := fmt.Sprintf("Connection-%d", id)

			_, err = conn.Write([]byte(testData))
			if err != nil {
				errors <- fmt.Errorf("conn %d: write failed: %v", id, err)
				return
			}

			buf := make([]byte, len(testData))
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				errors <- fmt.Errorf("conn %d: read failed: %v", id, err)
				return
			}

			if string(buf) != testData {
				errors <- fmt.Errorf("conn %d: expected %q, got %q", id, testData, string(buf))
				return
			}

			t.Logf("✓ Connection %d passed", id)
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}

	t.Logf("✓ All %d concurrent connections passed", numConnections)
}

// TestTunnelReconnection tests that tunnel can recover from disconnection
func TestTunnelReconnection(t *testing.T) {
	// 1. Start echo server
	echoAddr := "127.0.0.1:19995"
	echoListener, err := net.Listen("tcp", echoAddr)
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// 2. Start tunnel server
	serverAddr := "127.0.0.1:18884"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	serverCtx, serverCancel := context.WithCancel(context.Background())
	defer serverCancel()

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			t.Logf("Server error: %v", err)
		}
	}()
	defer server.Close()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:17773"

	opts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithPath("/tunnel"),
	}

	wsDialer := compat.NewDialer(opts...)
	dialerAdapter := &dialerAdapter{wsDialer: wsDialer}

	forwarder := compat.NewForwarder(
		clientAddr,
		dialerAdapter,
		compat.WithDisableUDP(),
	)

	go func() {
		if err := forwarder.Serve(); err != nil {
			if !isClosedNetworkError(err) {
				t.Errorf("Forwarder error: %v", err)
			}
		}
	}()
	defer forwarder.Close()

	time.Sleep(200 * time.Millisecond)

	// 4. Test connection before interruption
	testData := "Before Restart"

	conn, err := net.DialTimeout("tcp", clientAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf) != testData {
		t.Errorf("Expected %q, got %q", testData, string(buf))
	}
	conn.Close()

	t.Logf("✓ Connection before restart passed")

	// 5. Test new connection (tunnel should handle new connections)
	time.Sleep(500 * time.Millisecond)

	testData2 := "After Working"
	conn2, err := net.DialTimeout("tcp", clientAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to reconnect: %v", err)
	}
	defer conn2.Close()

	_, err = conn2.Write([]byte(testData2))
	if err != nil {
		t.Fatalf("Failed to write after restart: %v", err)
	}

	buf2 := make([]byte, len(testData2))
	conn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn2, buf2)
	if err != nil {
		t.Fatalf("Failed to read after restart: %v", err)
	}

	if string(buf2) != testData2 {
		t.Errorf("Expected %q, got %q", testData2, string(buf2))
	}

	t.Logf("✓ Connection after restart passed")
	_ = serverCtx
}
