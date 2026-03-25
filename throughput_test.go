package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
	"github.com/zijiren233/gwst/internal/crypto"
	"github.com/zijiren233/gwst/internal/utils"
)

// startBidirEchoTCP starts a TCP echo server where read and write are handled by
// separate goroutines, avoiding the single-goroutine io.Copy(c,c) deadlock that
// can occur when both send and receive buffers fill simultaneously under heavy load.
func startBidirEchoTCP(t *testing.T, addr string) func() {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("echo TCP listen %s: %v", addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var wg sync.WaitGroup
				wg.Add(1)
				ch := make(chan []byte, 512) // buffer up to 512 × 32KB = 16MB of pending writes
				go func() {
					defer wg.Done()
					buf := make([]byte, 32*1024)
					for {
						n, err := c.Read(buf)
						if n > 0 {
							tmp := make([]byte, n)
							copy(tmp, buf[:n])
							ch <- tmp
						}
						if err != nil {
							close(ch)
							return
						}
					}
				}()
				for data := range ch {
					if _, err := c.Write(data); err != nil {
						break
					}
				}
				wg.Wait()
			}(c)
		}
	}()
	return func() { ln.Close() }
}

// ─── 直接测量 CryptoConn 加密层吞吐 ─────────────────────────────────────────

func benchCrypto(t *testing.T, payloadKB int, withCrypto bool) {
	t.Helper()
	var cm utils.CryptoManager
	if withCrypto {
		var err error
		cm, err = crypto.NewManager([]byte("bench-key-16byte"))
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
	}

	label := "plaintext"
	if withCrypto {
		label = "AEGIS-128L"
	}

	payload := make([]byte, payloadKB*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	// stream mode only – WebSocket mode requires a real ws.Conn for framing
	c1, c2 := net.Pipe()
	enc := utils.NewCryptoConn(c1, cm, true)
	dec := utils.NewCryptoConn(c2, cm, true)

	const iters = 500
	done := make(chan int64, 1)
	go func() {
		var total int64
		buf := make([]byte, payloadKB*1024)
		for {
			n, err := io.ReadFull(dec, buf)
			total += int64(n)
			if err != nil {
				break
			}
		}
		done <- total
	}()

	start := time.Now()
	go func() {
		for i := 0; i < iters; i++ {
			enc.Write(payload)
		}
		enc.Close()
	}()
	total := <-done
	c2.Close()
	elapsed := time.Since(start)

	mbps := float64(total) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("mode=stream  crypto=%-10s  payloadKB=%3dKB  throughput=%7.1f MB/s  (%dMB / %.3fs)",
		label, payloadKB, mbps, total/(1024*1024), elapsed.Seconds())
}

func TestCryptoThroughput(t *testing.T) {
	for _, payloadKB := range []int{4, 16, 32, 64} {
		for _, enc := range []bool{false, true} {
			benchCrypto(t, payloadKB, enc)
		}
	}
}

// ─── 端到端加密隧道吞吐（经过 WebSocket 帧 + AEGIS） ────────────────────────

// TestTunnelThroughputUnencrypted measures end-to-end tunnel throughput without encryption.
// This tests the WebSocket framing overhead independent of crypto.
func TestTunnelThroughputUnencrypted(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:42011"
		serverAddr = "127.0.0.1:42012"
		clientAddr = "127.0.0.1:42013"
		path       = "/tput0"
		totalMB    = 32
	)
	defer startBidirEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, "")()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, "")()

	conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(120 * time.Second))

	const totalBytes = totalMB * 1024 * 1024
	chunk := make([]byte, 16*1024)
	for i := range chunk {
		chunk[i] = byte(i)
	}

	done := make(chan int64, 1)
	go func() {
		buf := make([]byte, 64*1024)
		var got int64
		for got < totalBytes {
			n, err := conn.Read(buf)
			got += int64(n)
			if err != nil {
				break
			}
		}
		done <- got
	}()

	start := time.Now()
	var sent int
	for sent < totalBytes {
		remain := totalBytes - sent
		w := len(chunk)
		if remain < w {
			w = remain
		}
		n, err := conn.Write(chunk[:w])
		sent += n
		if err != nil {
			t.Fatalf("write error after %dMB: %v", sent/(1024*1024), err)
		}
	}
	rx := <-done
	elapsed := time.Since(start)

	mbps := float64(rx) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("端到端明文隧道吞吐: %.1f MB/s  (tx=%dMB rx=%dMB elapsed=%.3fs)",
		mbps, sent/(1024*1024), rx/(1024*1024), elapsed.Seconds())
	if mbps < 5.0 {
		t.Errorf("吞吐量过低: %.1f MB/s (期望 >= 5 MB/s)", mbps)
	}
}

func TestTunnelThroughput(t *testing.T) {
	// Measure encrypted end-to-end tunnel throughput.
	// Uses multiple half-duplex connections (write-all, then read-all) with a large
	// OS receive buffer to accommodate the echo replies without stalling the forwarder.
	const (
		echoAddr   = "127.0.0.1:42001"
		serverAddr = "127.0.0.1:42002"
		clientAddr = "127.0.0.1:42003"
		path       = "/tput"
		encKey     = "throughput-key!!"
		chunkMB    = 4  // MB per connection
		numConns   = 4  // sequential connections (16MB total)
	)

	defer startBidirEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, encKey)()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, encKey)()

	payload := make([]byte, chunkMB*1024*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	start := time.Now()
	var totalBytes int64

	for i := 0; i < numConns; i++ {
		conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("conn %d dial: %v", i, err)
		}
		// Set a large OS receive buffer so the forwarder can write all echo replies
		// back without stalling while the test is in the write-all phase.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetReadBuffer(4 * 1024 * 1024)
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))

		// Write all payload in 16KB chunks.
		chunk := make([]byte, 16*1024)
		written := 0
		for written < len(payload) {
			w := len(chunk)
			if len(payload)-written < w {
				w = len(payload) - written
			}
			n, err := conn.Write(payload[written : written+w])
			written += n
			if err != nil {
				conn.Close()
				t.Fatalf("conn %d write at %d: %v", i, written, err)
			}
		}

		// Read back the full echo.
		received := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, received); err != nil {
			conn.Close()
			t.Fatalf("conn %d readfull: %v", i, err)
		}
		conn.Close()
		totalBytes += int64(len(payload))
	}

	elapsed := time.Since(start)
	mbps := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("端到端加密隧道吞吐: %.1f MB/s  (total=%dMB conns=%d elapsed=%.3fs)",
		mbps, int(totalBytes)/(1024*1024), numConns, elapsed.Seconds())

	if mbps < 5.0 {
		t.Errorf("吞吐量过低: %.1f MB/s (期望 >= 5 MB/s)", mbps)
	}

	fmt.Printf("\n[结论] 加密隧道端到端吞吐: %.1f MB/s (约 %.0f KB/s)\n", mbps, mbps*1024)
}

// ─── TCP 传输层加密隧道吞吐 ──────────────────────────────────────────────────

// startTCPTransportServer starts a tunnel server using raw TCP transport (no WebSocket).
// Encryption is stream-mode ([Len(2)][EncryptedPayload]) handled by CryptoConn.
func startTCPTransportServer(t *testing.T, serverAddr, targetAddr, encKey string) func() {
	t.Helper()
	opts := []compat.HandlerOption{
		compat.WithHandlerDefaultTargetAddr(targetAddr),
	}
	if encKey != "" {
		cm, err := crypto.NewManager([]byte(encKey[:crypto.KeySize]))
		if err != nil {
			t.Fatalf("startTCPTransportServer NewManager: %v", err)
		}
		opts = append(opts, compat.WithHandlerCryptoManager(cm))
	}
	handler := compat.NewHandler(opts...)
	srv := compat.NewServer("", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("tcp"),
	)
	go func() {
		if err := srv.Serve(); err != nil {
			t.Logf("tcp transport server error: %v", err)
		}
	}()
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("tcp transport server listen: %v", err)
	}
	return func() { srv.Close() }
}

// startTCPTransportForwarder starts a forwarder that dials the server using raw TCP transport.
func startTCPTransportForwarder(t *testing.T, listenAddr, serverAddr, encKey string) func() {
	t.Helper()
	dialOpts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithTransportType("tcp"),
	}
	if encKey != "" {
		dialOpts = append(dialOpts, compat.WithEncryptionKey(encKey))
	}
	d := compat.NewDialer(dialOpts...)
	fwd := compat.NewForwarder(listenAddr, &dialerAdapter{wsDialer: d}, compat.WithDisableUDP())
	go func() {
		if err := fwd.Serve(); err != nil && !isClosedNetworkError(err) {
			t.Logf("tcp transport forwarder error: %v", err)
		}
	}()
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("tcp transport forwarder listen: %v", err)
	}
	return func() { fwd.Close() }
}

func TestTCPTransportThroughput(t *testing.T) {
	// Measure encrypted TCP-transport tunnel throughput.
	// TCP transport uses stream-mode framing ([Len(2)][AEGIS-encrypted payload]),
	// which is lighter than WebSocket (no HTTP upgrade, no WS framing overhead).
	const (
		echoAddr   = "127.0.0.1:45001"
		serverAddr = "127.0.0.1:45002"
		clientAddr = "127.0.0.1:45003"
		encKey     = "tcp-tpt-key!!!!!"
		chunkMB    = 4 // MB per connection
		numConns   = 4 // sequential connections (16MB total)
	)

	defer startBidirEchoTCP(t, echoAddr)()
	defer startTCPTransportServer(t, serverAddr, echoAddr, encKey)()
	defer startTCPTransportForwarder(t, clientAddr, serverAddr, encKey)()

	payload := make([]byte, chunkMB*1024*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	start := time.Now()
	var totalBytes int64

	for i := 0; i < numConns; i++ {
		conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("conn %d dial: %v", i, err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetReadBuffer(4 * 1024 * 1024)
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))

		chunk := make([]byte, 16*1024)
		written := 0
		for written < len(payload) {
			w := len(chunk)
			if len(payload)-written < w {
				w = len(payload) - written
			}
			n, err := conn.Write(payload[written : written+w])
			written += n
			if err != nil {
				conn.Close()
				t.Fatalf("conn %d write at %dKB: %v", i, written/1024, err)
			}
		}

		received := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, received); err != nil {
			conn.Close()
			t.Fatalf("conn %d readfull: %v", i, err)
		}
		conn.Close()
		totalBytes += int64(len(payload))
	}

	elapsed := time.Since(start)
	mbps := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("TCP传输加密隧道吞吐: %.1f MB/s  (total=%dMB conns=%d elapsed=%.3fs)",
		mbps, int(totalBytes)/(1024*1024), numConns, elapsed.Seconds())

	if mbps < 5.0 {
		t.Errorf("吞吐量过低: %.1f MB/s (期望 >= 5 MB/s)", mbps)
	}

	fmt.Printf("\n[结论] TCP传输加密隧道吞吐: %.1f MB/s (约 %.0f KB/s)\n", mbps, mbps*1024)
}

// ─── QUIC 传输层加密隧道吞吐 ──────────────────────────────────────────────────

// writeTempCertFiles generates a self-signed ECDSA cert and writes PEM files to temp paths.
func writeTempCertFiles(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "gwst-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cf, err := os.CreateTemp("", "gwst-cert-*.pem")
	if err != nil {
		t.Fatalf("create cert tempfile: %v", err)
	}
	if _, err := cf.Write(certPEM); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	cf.Close()

	kf, err := os.CreateTemp("", "gwst-key-*.pem")
	if err != nil {
		t.Fatalf("create key tempfile: %v", err)
	}
	if _, err := kf.Write(keyPEM); err != nil {
		t.Fatalf("write key: %v", err)
	}
	kf.Close()

	return cf.Name(), kf.Name(), func() {
		os.Remove(cf.Name())
		os.Remove(kf.Name())
	}
}

func startQUICTransportServer(t *testing.T, serverAddr, targetAddr, encKey, certFile, keyFile string) func() {
	t.Helper()
	opts := []compat.HandlerOption{compat.WithHandlerDefaultTargetAddr(targetAddr)}
	if encKey != "" {
		cm, err := crypto.NewManager([]byte(encKey[:crypto.KeySize]))
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		opts = append(opts, compat.WithHandlerCryptoManager(cm))
	}
	handler := compat.NewHandler(opts...)
	srv := compat.NewServer("", handler,
		compat.WithListenAddr(serverAddr),
		compat.WithTransport("quic"),
		compat.WithTLS(certFile, keyFile),
	)
	go func() {
		if err := srv.Serve(); err != nil {
			t.Logf("quic server error: %v", err)
		}
	}()
	if err := srv.WaitListen(); err != nil {
		t.Fatalf("quic server listen: %v", err)
	}
	return func() { srv.Close() }
}

func startQUICTransportForwarder(t *testing.T, listenAddr, serverAddr, encKey string) func() {
	t.Helper()
	dialOpts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithTransportType("quic"),
		compat.WithInsecure(true),
	}
	if encKey != "" {
		dialOpts = append(dialOpts, compat.WithEncryptionKey(encKey))
	}
	d := compat.NewDialer(dialOpts...)
	fwd := compat.NewForwarder(listenAddr, &dialerAdapter{wsDialer: d}, compat.WithDisableUDP())
	go func() {
		if err := fwd.Serve(); err != nil && !isClosedNetworkError(err) {
			t.Logf("quic forwarder error: %v", err)
		}
	}()
	<-fwd.OnListened()
	if err := fwd.ListenErr(); err != nil {
		t.Fatalf("quic forwarder listen: %v", err)
	}
	return func() { fwd.Close() }
}

func TestQUICTransportThroughput(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:46001"
		serverAddr = "127.0.0.1:46002"
		clientAddr = "127.0.0.1:46003"
		encKey     = "quic-tpt-test-k!"
		chunkMB    = 4
		numConns   = 4
	)

	certFile, keyFile, certCleanup := writeTempCertFiles(t)
	defer certCleanup()

	defer startBidirEchoTCP(t, echoAddr)()
	defer startQUICTransportServer(t, serverAddr, echoAddr, encKey, certFile, keyFile)()
	defer startQUICTransportForwarder(t, clientAddr, serverAddr, encKey)()

	payload := make([]byte, chunkMB*1024*1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	start := time.Now()
	var totalBytes int64

	for i := range numConns {
		conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("conn %d dial: %v", i, err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetReadBuffer(4 * 1024 * 1024)
		}
		conn.SetDeadline(time.Now().Add(60 * time.Second))

		chunk := make([]byte, 16*1024)
		written := 0
		for written < len(payload) {
			w := len(chunk)
			if len(payload)-written < w {
				w = len(payload) - written
			}
			n, err := conn.Write(payload[written : written+w])
			written += n
			if err != nil {
				conn.Close()
				t.Fatalf("conn %d write: %v", i, err)
			}
		}

		received := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, received); err != nil {
			conn.Close()
			t.Fatalf("conn %d readfull: %v", i, err)
		}
		conn.Close()
		totalBytes += int64(len(payload))
	}

	elapsed := time.Since(start)
	mbps := float64(totalBytes) / elapsed.Seconds() / (1024 * 1024)
	t.Logf("QUIC传输加密隧道吞吐: %.1f MB/s  (total=%dMB conns=%d elapsed=%.3fs)",
		mbps, int(totalBytes)/(1024*1024), numConns, elapsed.Seconds())

	if mbps < 5.0 {
		t.Errorf("吞吐量过低: %.1f MB/s (期望 >= 5 MB/s)", mbps)
	}
	fmt.Printf("\n[结论] QUIC传输加密隧道吞吐: %.1f MB/s (约 %.0f KB/s)\n", mbps, mbps*1024)
}


