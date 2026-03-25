package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
	"github.com/zijiren233/gwst/internal/crypto"
)

// NOTE: dialerAdapter is defined in main.go (same package).
// NOTE: isClosedNetworkError is defined in integration_test.go (same package).

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// startEchoTCP starts a TCP echo server and returns its address and a cleanup func.
func startEchoTCP(t *testing.T, addr string) func() {
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
				io.Copy(c, c)
			}(c)
		}
	}()
	return func() { ln.Close() }
}

// startEchoUDP starts a UDP echo server and returns its address and a cleanup func.
func startEchoUDP(t *testing.T, addr string) func() {
	t.Helper()
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("echo UDP listen %s: %v", addr, err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], src)
		}
	}()
	return func() { conn.Close() }
}

// startTunnelServer 启动隧道服务端，返回 cleanup func。
// encKey 为空时不启用加密；否则使用 AEGIS-128L（取前 KeySize 字节）。
func startTunnelServer(t *testing.T, serverAddr, targetAddr, path, encKey string) func() {
	t.Helper()
	opts := []compat.HandlerOption{
		compat.WithHandlerDefaultTargetAddr(targetAddr),
	}
	if encKey != "" {
		cm, err := crypto.NewManager([]byte(encKey[:crypto.KeySize]))
		if err != nil {
			t.Fatalf("startTunnelServer NewManager: %v", err)
		}
		opts = append(opts, compat.WithHandlerCryptoManager(cm))
	}
	handler := compat.NewHandler(opts...)
	srv := compat.NewServer(path, handler, compat.WithListenAddr(serverAddr))
	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			t.Logf("tunnel server error: %v", err)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	return func() { srv.Close() }
}

// startForwarder 启动客户端 forwarder，返回 cleanup func。
func startForwarder(t *testing.T, listenAddr, serverAddr, path string, disableUDP, disableTCP bool, encKey string) func() {
	t.Helper()
	dialOpts := []compat.ConnectOption{
		compat.WithAddr(serverAddr),
		compat.WithPath(path),
	}
	if encKey != "" {
		dialOpts = append(dialOpts, compat.WithEncryptionKey(encKey))
	}
	d := compat.NewDialer(dialOpts...)
	fwdOpts := []compat.ForwarderOption{}
	if disableUDP {
		fwdOpts = append(fwdOpts, compat.WithDisableUDP())
	}
	if disableTCP {
		fwdOpts = append(fwdOpts, compat.WithDisableTCP())
	}
	fwd := compat.NewForwarder(listenAddr, &dialerAdapter{wsDialer: d}, fwdOpts...)
	go func() {
		if err := fwd.Serve(); err != nil && !isClosedNetworkError(err) {
			t.Logf("forwarder error: %v", err)
		}
	}()
	time.Sleep(150 * time.Millisecond)
	return func() { fwd.Close() }
}

// memStats captures heap-alloc in MB and live goroutine count after a GC.
func memStats(t *testing.T, label string) (goroutines int, allocMB uint64) {
	t.Helper()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	g := runtime.NumGoroutine()
	t.Logf("[%s] goroutines=%d  heapAlloc=%dMB  heapInUse=%dMB",
		label, g, ms.HeapAlloc/(1<<20), ms.HeapInuse/(1<<20))
	return g, ms.HeapAlloc / (1 << 20)
}

// sendRecvTCP dials clientAddr, writes data, reads it back, checks equality.
func sendRecvTCP(t *testing.T, clientAddr, payload string, timeout time.Duration) error {
	t.Helper()
	conn, err := net.DialTimeout("tcp", clientAddr, timeout)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if _, err := fmt.Fprint(conn, payload); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, len(payload))
	conn.SetReadDeadline(time.Now().Add(timeout))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf) != payload {
		return fmt.Errorf("echo mismatch: want %q got %q", payload, buf)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1: High-Concurrency TCP – no encryption
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureTCPNoCrypto(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:41001"
		serverAddr = "127.0.0.1:41002"
		clientAddr = "127.0.0.1:41003"
		path       = "/p1"
		concur     = 200
		perConn    = 5
	)
	defer startEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, "")()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, "")()

	g0, _ := memStats(t, "before")

	var wg sync.WaitGroup
	var ok, fail int32
	for i := 0; i < concur; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := fmt.Sprintf("msg-%d", id)
			for j := 0; j < perConn; j++ {
				if err := sendRecvTCP(t, clientAddr, payload, 5*time.Second); err != nil {
					atomic.AddInt32(&fail, 1)
					t.Logf("conn %d iter %d: %v", id, j, err)
					return
				}
			}
			atomic.AddInt32(&ok, 1)
		}(i)
		time.Sleep(3 * time.Millisecond) // gentle ramp
	}
	wg.Wait()

	g1, _ := memStats(t, "after")
	t.Logf("ok=%d fail=%d", ok, fail)

	if fail > concur/10 {
		t.Errorf("failure rate too high: %d/%d", fail, concur)
	}
	if g1-g0 > 30 {
		t.Errorf("goroutine leak: +%d (want ≤30)", g1-g0)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2: High-Concurrency TCP – with AEGIS-128L encryption
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureTCPWithCrypto(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:41011"
		serverAddr = "127.0.0.1:41012"
		clientAddr = "127.0.0.1:41013"
		path       = "/p2"
		concur     = 150
		perConn    = 5
		encKey     = "pressure-test-key!!"
	)

	defer startEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, encKey)()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, encKey)()

	g0, _ := memStats(t, "before")

	var wg sync.WaitGroup
	var ok, fail int32
	for i := 0; i < concur; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := fmt.Sprintf("enc-%d", id)
			for j := 0; j < perConn; j++ {
				if err := sendRecvTCP(t, clientAddr, payload, 5*time.Second); err != nil {
					atomic.AddInt32(&fail, 1)
					return
				}
			}
			atomic.AddInt32(&ok, 1)
		}(i)
		time.Sleep(4 * time.Millisecond)
	}
	wg.Wait()

	g1, _ := memStats(t, "after")
	t.Logf("ok=%d fail=%d", ok, fail)

	if fail > concur/10 {
		t.Errorf("failure rate too high: %d/%d", fail, concur)
	}
	if g1-g0 > 30 {
		t.Errorf("goroutine leak: +%d (want ≤30)", g1-g0)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3: UDP pressure – no encryption
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureUDPNoCrypto(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:41021"
		serverAddr = "127.0.0.1:41022"
		clientAddr = "127.0.0.1:41023"
		path       = "/p3"
		clients    = 10
		perClient  = 15
	)
	defer startEchoUDP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, "")()

	// Use a very short UDP idle timeout so goroutines clean up during the test.
	d := compat.NewDialer(
		compat.WithAddr(serverAddr),
		compat.WithPath(path),
	)
	fwd := compat.NewForwarder(clientAddr, &dialerAdapter{wsDialer: d},
		compat.WithDisableTCP(),
		compat.WithUDPPoolSize(clients+5),
		compat.WithUDPPoolPreAlloc(true),
		compat.WithUDPIdleTimeout(5*time.Second),
		compat.WithUDPCleanupInterval(2*time.Second),
	)
	go func() {
		if err := fwd.Serve(); err != nil && !isClosedNetworkError(err) {
			t.Logf("forwarder error: %v", err)
		}
	}()
	defer fwd.Close()
	time.Sleep(300 * time.Millisecond)

	g0, _ := memStats(t, "before")

	var wg sync.WaitGroup
	var ok, fail int32
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			addr, _ := net.ResolveUDPAddr("udp", clientAddr)
			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				atomic.AddInt32(&fail, 1)
				return
			}
			defer conn.Close()

			payload := []byte(fmt.Sprintf("udp-%d", id))

			// Warm up: send a few priming packets to open the tunnel.
			for k := 0; k < 3; k++ {
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				conn.Write(payload)
				time.Sleep(80 * time.Millisecond)
			}

			// Now the tunnel is established — read the first echoed packet.
			buf := make([]byte, len(payload))
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := conn.Read(buf); err != nil {
				// The echo may have been lost; send one more and try again.
				conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				conn.Write(payload)
				conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Read(buf); err != nil {
					atomic.AddInt32(&fail, 1)
					t.Logf("client %d: initial read failed: %v", id, err)
					return
				}
			}

			// Main send/receive loop.
			for j := 0; j < perClient; j++ {
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					atomic.AddInt32(&fail, 1)
					return
				}
				if _, err := conn.Read(buf); err != nil {
					atomic.AddInt32(&fail, 1)
					return
				}
				time.Sleep(30 * time.Millisecond)
			}
			atomic.AddInt32(&ok, 1)
		}(i)
		time.Sleep(50 * time.Millisecond) // stagger connections
	}
	wg.Wait()

	// Allow the short-timeout UDP cleanup to run.
	time.Sleep(7 * time.Second)

	g1, _ := memStats(t, "after")
	t.Logf("ok=%d fail=%d", ok, fail)

	if fail > clients/3 {
		t.Errorf("UDP failure rate too high: %d/%d", fail, clients)
	}
	if g1-g0 > 20 {
		t.Errorf("goroutine leak: +%d (want ≤20)", g1-g0)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4: Large payload / throughput
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureLargePayload(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:41031"
		serverAddr = "127.0.0.1:41032"
		clientAddr = "127.0.0.1:41033"
		path       = "/p4"
		payloadMB  = 4 // MB per connection
		concur     = 10
	)
	defer startEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, "")()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, "")()

	payload := make([]byte, payloadMB*1<<20)
	for i := range payload {
		payload[i] = byte(i)
	}

	var wg sync.WaitGroup
	var ok, fail int32
	for i := 0; i < concur; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", clientAddr, 10*time.Second)
			if err != nil {
				atomic.AddInt32(&fail, 1)
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))

			if _, err := conn.Write(payload); err != nil {
				atomic.AddInt32(&fail, 1)
				return
			}
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, received); err != nil {
				atomic.AddInt32(&fail, 1)
				return
			}
			// Spot-check first and last byte
			if received[0] != payload[0] || received[len(payload)-1] != payload[len(payload)-1] {
				atomic.AddInt32(&fail, 1)
				return
			}
			atomic.AddInt32(&ok, 1)
		}()
	}
	wg.Wait()
	t.Logf("large-payload: ok=%d fail=%d  (%dMB × %d conn)", ok, fail, payloadMB, concur)
	if fail > 0 {
		t.Errorf("large payload failures: %d", fail)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5: Rapid connect/disconnect – goroutine & memory stability
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureRapidCycling(t *testing.T) {
	const (
		echoAddr   = "127.0.0.1:41041"
		serverAddr = "127.0.0.1:41042"
		clientAddr = "127.0.0.1:41043"
		path       = "/p5"
		rounds     = 300
		concur     = 20
	)
	defer startEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, "")()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, "")()

	g0, m0 := memStats(t, "before")

	sem := make(chan struct{}, concur)
	var wg sync.WaitGroup
	var ok, fail int32

	for i := 0; i < rounds; i++ {
		sem <- struct{}{}
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := sendRecvTCP(t, clientAddr, fmt.Sprintf("cycle-%d", id), 5*time.Second); err != nil {
				atomic.AddInt32(&fail, 1)
			} else {
				atomic.AddInt32(&ok, 1)
			}
		}(i)
	}
	wg.Wait()

	// Wait for server-side cleanup
	time.Sleep(500 * time.Millisecond)
	g1, m1 := memStats(t, "after")

	t.Logf("rapid-cycling: ok=%d fail=%d  goroutines: %d→%d  mem: %dMB→%dMB",
		ok, fail, g0, g1, m0, m1)

	if fail > rounds/20 {
		t.Errorf("failure rate too high: %d/%d", fail, rounds)
	}
	if g1-g0 > 30 {
		t.Errorf("goroutine leak after rapid cycling: +%d (want ≤30)", g1-g0)
	}
	// Memory should not grow by more than 20 MB after GC
	memGrowth := int64(m1) - int64(m0)
	if memGrowth > 20 {
		t.Errorf("memory growth after rapid cycling: +%dMB (want ≤20MB)", memGrowth)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6: Encrypted long-lived connections – memory stability
// ─────────────────────────────────────────────────────────────────────────────

func TestPressureEncryptedLongLived(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping long-lived test in short mode")
	}
	const (
		echoAddr   = "127.0.0.1:41051"
		serverAddr = "127.0.0.1:41052"
		clientAddr = "127.0.0.1:41053"
		path       = "/p6"
		encKey     = "long-lived-key!!!"
		numConns   = 20
		duration   = 6 * time.Second
	)

	defer startEchoTCP(t, echoAddr)()
	defer startTunnelServer(t, serverAddr, echoAddr, path, encKey)()
	defer startForwarder(t, clientAddr, serverAddr, path, true, false, encKey)()

	g0, m0 := memStats(t, "before")

	conns := make([]net.Conn, numConns)
	for i := range conns {
		c, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns[i] = c
	}

	var totalMsgs int32
	var wg sync.WaitGroup
	done := make(chan struct{})

	for i, c := range conns {
		wg.Add(1)
		go func(id int, conn net.Conn) {
			defer wg.Done()
			payload := fmt.Sprintf("keepalive-%d", id)
			buf := make([]byte, len(payload))
			ticker := time.NewTicker(200 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-ticker.C:
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					if _, err := fmt.Fprint(conn, payload); err != nil {
						return
					}
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					atomic.AddInt32(&totalMsgs, 1)
				}
			}
		}(i, c)
	}

	// Sample memory mid-test
	time.Sleep(duration / 2)
	_, m_mid := memStats(t, "mid")

	time.Sleep(duration / 2)
	close(done)
	wg.Wait()

	for _, c := range conns {
		c.Close()
	}
	time.Sleep(500 * time.Millisecond)

	g1, m1 := memStats(t, "after")
	t.Logf("total messages exchanged: %d", totalMsgs)
	t.Logf("memory: before=%dMB mid=%dMB after=%dMB", m0, m_mid, m1)

	if int64(m_mid)-int64(m0) > 30 {
		t.Errorf("memory grew too much during sustained load: +%dMB mid (want ≤30)", int64(m_mid)-int64(m0))
	}
	if g1-g0 > 30 {
		t.Errorf("goroutine leak: +%d (want ≤30)", g1-g0)
	}
}
