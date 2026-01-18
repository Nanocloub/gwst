package compat_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host)
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

func TestGenerateSelfSignedCertWithECC(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host, compat.WithECC())
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

func TestGenerateSelfSignedCertWithEd25519(t *testing.T) {
	host := "localhost"

	cert, err := compat.GenerateSelfSignedCert(host, compat.WithEd25519())
	if err != nil {
		t.Fatalf("Failed to generate self-signed certificate: %v", err)
	}

	if len(cert.Certificate) == 0 {
		t.Fatalf("Certificate is empty")
	}

	t.Logf("Generated certificate: %+v", cert)
}

// TestWsServerAndDialer is a manual integration test that requires manual setup
// and cleanup. It is disabled by default to prevent hanging test runs.
// To run this test manually, use:
//   go test -timeout 30s -run TestWsServerAndDialer ./...
// NOTE: This test will hang for 30 seconds as designed for manual testing.
func TestWsServerAndDialer(t *testing.T) {
	// Create a context with timeout to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Setup backend echo server
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		ln, err := net.Listen("tcp", "127.0.0.1:8081")
		if err != nil {
			t.Logf("Backend listen error: %v", err)
			return
		}
		defer ln.Close()

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			ln.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second))
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}

			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	// Setup WebSocket server
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		wss := compat.NewServer(
			"/ws",
			compat.NewHandler(
				compat.WithHandlerDefaultTargetAddr("127.0.0.1:8081"),
			),
			compat.WithListenAddr("0.0.0.0:8080"),
			compat.WithTLS("", ""),
			compat.WithServerName("www.microstft.com"),
			compat.WithSelfSignedCert(compat.WithECC()),
		)
		_ = wss.Serve()
	}()

	time.Sleep(500 * time.Millisecond)

	// Test TCP connection
	wsc := compat.NewDialer(
		compat.WithAddr("127.0.0.1:8080"),
		compat.WithPath("/ws"),
		compat.WithDialTLS(true),
		compat.WithDialServerName("www.microstft.com"),
		compat.WithInsecure(true),
	)

	conn, err := wsc.DialTCP()
	if err != nil {
		t.Fatalf("Failed to dial TCP: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Failed to write: %v", err)
	}

	t.Logf("✓ WebSocket TCP connection test passed")

	// Wait for cleanup with timeout
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
	}
}
