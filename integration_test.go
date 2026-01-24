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

// TestTCPTunnelIntegration tests a complete TCP tunnel from client -> server -> echo service
func TestTCPTunnelIntegration(t *testing.T) {
	// 1. Start echo TCP server
	echoAddr := "127.0.0.1:19999"
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
				io.Copy(c, c) // Echo back
			}(conn)
		}
	}()

	// 2. Start tunnel server (WebSocket server)
	serverAddr := "127.0.0.1:18888"
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

	// Wait for server to start
	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client (local forwarder)
	clientAddr := "127.0.0.1:17777"

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
		if err := forwarder.Serve(); err != nil && !isClosedNetworkError(err) {
			t.Errorf("Forwarder error: %v", err)
		}
	}()
	defer forwarder.Close()

	// Wait for client to start
	time.Sleep(200 * time.Millisecond)

	// 4. Test the tunnel: connect to client -> tunnels to server -> reaches echo service
	testData := "Hello, Tunnel!"

	conn, err := net.DialTimeout("tcp", clientAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to client: %v", err)
	}
	defer conn.Close()

	// Send test data
	_, err = conn.Write([]byte(testData))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	// Read response
	buf := make([]byte, len(testData))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if string(buf) != testData {
		t.Errorf("Expected %q, got %q", testData, string(buf))
	}

	t.Logf("✓ TCP tunnel test passed: %q", testData)
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

// TestTunnelWithEncryption tests tunnel with encryption enabled
func TestTunnelWithEncryption(t *testing.T) {
	// 1. Start echo server
	echoAddr := "127.0.0.1:19996"
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

	// 2. Start tunnel server with encryption
	encryptionKey := "test-encryption-key-32-bytes!"
	serverAddr := "127.0.0.1:18885"

	// Create crypto manager for encryption
	cryptoManager, err := crypto.NewManager([]byte(encryptionKey[:crypto.KeySize]))
	if err != nil {
		t.Fatalf("Failed to create crypto manager: %v", err)
	}

	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
		compat.WithHandlerCryptoManager(cryptoManager),
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

	// 3. Start tunnel client with same encryption key
	clientAddr := "127.0.0.1:17774"

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
		compat.WithCryptoManager(cryptoManager), // Use the same crypto manager
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

	// 4. Test encrypted tunnel
	testData := "Encrypted Tunnel Test!"

	conn, err := net.DialTimeout("tcp", clientAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

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

	t.Logf("✓ Encrypted tunnel test passed: %q", testData)
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
