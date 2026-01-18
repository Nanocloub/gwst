package main

import (
	"io"
	"net"
	"runtime"
	"testing"
	"time"
)

// TestMinimalGoroutineLeak tests a simple echo server to identify goroutine leaks
func TestMinimalGoroutineLeak(t *testing.T) {
	// Start a simple echo server
	listener, err := net.Listen("tcp", "127.0.0.1:30000")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Record initial goroutines
	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	t.Logf("Initial: %d goroutines", initialGoroutines)

	// Create and close 100 connections
	numConnections := 100
	for i := 0; i < numConnections; i++ {
		conn, err := net.Dial("tcp", "127.0.0.1:30000")
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}

		// Send some data
		conn.Write([]byte("test"))

		// Read response
		buf := make([]byte, 4)
		conn.Read(buf)

		// Close
		conn.Close()
	}

	// Close listener
	listener.Close()

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	finalGoroutines := runtime.NumGoroutine()
	increase := finalGoroutines - initialGoroutines

	t.Logf("Final: %d goroutines (+%d)", finalGoroutines, increase)

	if increase > 20 {
		t.Errorf("Too many goroutines leaked: +%d", increase)
	}
}
