package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zijiren233/gwst/compat"
)

// TestHighConcurrency tests the server under high concurrent load
func TestHighConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high concurrency test in short mode")
	}

	// 1. Start echo server
	echoAddr := "127.0.0.1:29999"
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
	serverAddr := "127.0.0.1:28888"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			if !isClosedNetworkError(err) {
				t.Logf("Server error: %v", err)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:27777"

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

	time.Sleep(200 * time.Millisecond)

	// Record initial memory and goroutines
	runtime.GC()
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)
	initialGoroutines := runtime.NumGoroutine()

	t.Logf("Initial state: Goroutines=%d, Alloc=%dMB", initialGoroutines, initialMem.Alloc/1024/1024)

	// 4. Create many concurrent connections
	numConnections := 100
	var wg sync.WaitGroup
	var successCount int32
	var failCount int32
	errors := make(chan error, numConnections)

	for i := 0; i < numConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
			if err != nil {
				atomic.AddInt32(&failCount, 1)
				errors <- fmt.Errorf("conn %d: dial failed: %v", id, err)
				return
			}
			defer conn.Close()

			// Send and receive data
			testData := fmt.Sprintf("HeavyLoad-%d", id)
			for j := 0; j < 10; j++ {
				_, err := conn.Write([]byte(testData))
				if err != nil {
					atomic.AddInt32(&failCount, 1)
					errors <- fmt.Errorf("conn %d: write failed: %v", id, err)
					return
				}

				buf := make([]byte, len(testData))
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err = io.ReadFull(conn, buf)
				if err != nil {
					atomic.AddInt32(&failCount, 1)
					errors <- fmt.Errorf("conn %d: read failed: %v", id, err)
					return
				}
			}

			atomic.AddInt32(&successCount, 1)
		}(i)

		// Stagger connection creation to avoid overwhelming the server
		time.Sleep(5 * time.Millisecond)
	}

	wg.Wait()
	close(errors)

	// All client connections are now closed
	// Now close server and forwarder
	forwarder.Close()

	// Close the server (this stops accepting new connections)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	// Give longer time for in-flight requests to finish
	time.Sleep(2 * time.Second)

	// Check for errors
	errorCount := 0
	for err := range errors {
		if errorCount < 5 {
			t.Logf("Error: %v", err)
		}
		errorCount++
	}

	// Give time for cleanup goroutines to fully exit
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	finalGoroutines := runtime.NumGoroutine()

	memoryIncrease := (finalMem.Alloc - initialMem.Alloc) / 1024 / 1024
	goroutineIncrease := finalGoroutines - initialGoroutines

	t.Logf("Final state: Goroutines=%d (+%d), Alloc=%dMB (+%dMB)",
		finalGoroutines, goroutineIncrease, finalMem.Alloc/1024/1024, memoryIncrease)

	t.Logf("Results: Success=%d, Fail=%d, Errors=%d", successCount, failCount, errorCount)

	// With proper cleanup, goroutine increase should be minimal (< 20)
	// This verifies there are no goroutine leaks
	if goroutineIncrease > 20 {
		t.Errorf("Goroutine leak detected: +%d (expected < 20)", goroutineIncrease)
	}

	if memoryIncrease > 50 {
		t.Errorf("Excessive memory increase: +%dMB (expected < 50MB)", memoryIncrease)
	}

	if failCount > int32(numConnections/10) {
		t.Errorf("Too many failures: %d/%d (expected < 10%%)", failCount, numConnections)
	}
}

// TestLongConnections tests server with long-lived connections
func TestLongConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping long connections test in short mode")
	}

	// 1. Start echo server
	echoAddr := "127.0.0.1:29998"
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
	serverAddr := "127.0.0.1:28887"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			if !isClosedNetworkError(err) {
				t.Logf("Server error: %v", err)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:27776"

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

	time.Sleep(200 * time.Millisecond)

	// Record initial state
	runtime.GC()
	var initialMem runtime.MemStats
	runtime.ReadMemStats(&initialMem)
	initialGoroutines := runtime.NumGoroutine()

	t.Logf("Initial state: Goroutines=%d, Alloc=%dMB", initialGoroutines, initialMem.Alloc/1024/1024)

	// 4. Create connections and keep them open for a while
	numConnections := 20
	conns := make([]net.Conn, numConnections)

	// Open all connections
	for i := 0; i < numConnections; i++ {
		conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		conns[i] = conn
	}

	// Periodically send/receive data
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var totalMessages int32
	var wg sync.WaitGroup
	done := make(chan struct{})
	
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ticker.C:
				for i, conn := range conns {
					if conn == nil {
						continue
					}
					testData := fmt.Sprintf("Keep-Alive-%d", i)
					_, err := conn.Write([]byte(testData))
					if err != nil {
						t.Logf("Write error on conn %d: %v", i, err)
						conn.Close()
						conns[i] = nil
						continue
					}

					buf := make([]byte, len(testData))
					conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, err = io.ReadFull(conn, buf)
					if err != nil {
						t.Logf("Read error on conn %d: %v", i, err)
						conn.Close()
						conns[i] = nil
						continue
					}
					atomic.AddInt32(&totalMessages, 1)
				}
			case <-done:
				return
			}
		}
	}()

	// Keep connections open for 5 seconds
	time.Sleep(5 * time.Second)
	close(done)
	wg.Wait()  // Wait for goroutine to finish before closing connections

	// Close all connections
	for _, conn := range conns {
		if conn != nil {
			conn.Close()
		}
	}

	// Close server and wait for connections to complete
	forwarder.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	time.Sleep(1 * time.Second)

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	// Record final state
	var finalMem runtime.MemStats
	runtime.ReadMemStats(&finalMem)
	finalGoroutines := runtime.NumGoroutine()

	memoryIncrease := (finalMem.Alloc - initialMem.Alloc) / 1024 / 1024
	goroutineIncrease := finalGoroutines - initialGoroutines

	t.Logf("Final state: Goroutines=%d (+%d), Alloc=%dMB (+%dMB)",
		finalGoroutines, goroutineIncrease, finalMem.Alloc/1024/1024, memoryIncrease)
	t.Logf("Total messages: %d", totalMessages)

	// With proper cleanup, goroutine increase should be minimal
	if goroutineIncrease > 40 {
		t.Errorf("Too many goroutines leaked: +%d (expected < 40)", goroutineIncrease)
	}
}

// TestMemoryLeakDetection uses pprof to detect memory leaks
func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}

	// Disable GC temporarily
	oldPercent := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldPercent)

	// 1. Start echo server
	echoAddr := "127.0.0.1:29997"
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
	serverAddr := "127.0.0.1:28886"
	handler := compat.NewHandler(
		compat.WithHandlerDefaultTargetAddr(echoAddr),
	)

	server := compat.NewServer("/tunnel", handler,
		compat.WithListenAddr(serverAddr),
	)

	go func() {
		if err := server.Serve(); err != nil && err != http.ErrServerClosed {
			if !isClosedNetworkError(err) {
				t.Logf("Server error: %v", err)
			}
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// 3. Start tunnel client
	clientAddr := "127.0.0.1:27775"

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

	time.Sleep(200 * time.Millisecond)

	// Test memory growth over multiple cycles
	const cycles = 10
	const connectionsPerCycle = 50
	memSamples := make([]uint64, cycles)

	for cycle := 0; cycle < cycles; cycle++ {
		// Create and close connections
		for i := 0; i < connectionsPerCycle; i++ {
			conn, err := net.DialTimeout("tcp", clientAddr, 5*time.Second)
			if err != nil {
				t.Logf("Cycle %d: dial error: %v", cycle, err)
				continue
			}

			testData := "leak-test"
			conn.Write([]byte(testData))

			buf := make([]byte, len(testData))
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			io.ReadFull(conn, buf)

			conn.Close()
		}

		// Sample memory
		time.Sleep(100 * time.Millisecond)
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memSamples[cycle] = m.Alloc

		t.Logf("Cycle %d: Alloc=%dMB", cycle, m.Alloc/1024/1024)
	}

	// Check for linear memory growth (leak)
	// Calculate slope of memory growth
	if cycles >= 2 {
		firstHalf := memSamples[cycles/2-1]
		secondHalf := memSamples[cycles-1]

		// Handle potential decrease (GC)
		var growthRate uint64
		if secondHalf > firstHalf {
			growthRate = (secondHalf - firstHalf) / uint64(cycles/2)
		} else {
			growthRate = 0
		}

		t.Logf("Memory growth rate: %dMB per cycle", growthRate/1024/1024)

		// If memory is growing more than 10MB per cycle, it might indicate a leak
		// Note: With goroutine cleanup delays, some memory growth is expected
		if growthRate > 10*1024*1024 {
			t.Errorf("Potential memory leak detected: growing at %dMB per cycle", growthRate/1024/1024)
		}
	}

	// Close server and wait for connections to complete
	forwarder.Close()
	server.Close()
}
