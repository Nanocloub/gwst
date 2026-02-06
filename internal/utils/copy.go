package utils

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	DefaultWriteTimeout = 15 * time.Second
	// DefaultBufferSize 默认缓冲区大小 16KB
	DefaultBufferSize = 16 * 1024
	// MaxUDPSize UDP 最大数据包大小
	MaxUDPSize = 65535
	// UDPBufferSize 包含加密开销的 UDP 缓冲区大小 (65535 + 32 + 2)
	UDPBufferSize = MaxUDPSize + 64
)

// DeadlineWriter 接口用于支持写入期限的 io.Writer
type DeadlineWriter interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

// CryptoManager 定义加密/解密操作接口
type CryptoManager interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	EncryptTo(dst, plaintext []byte) ([]byte, error)
	DecryptTo(dst, ciphertext []byte) ([]byte, error)
}

var sharedBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, DefaultBufferSize)
		return &buffer
	},
}

// NewBufferPool creates a new buffer pool with specified size
func NewBufferPool(size int) *sync.Pool {
	if size == DefaultBufferSize || size <= 0 {
		return &sharedBufferPool
	}

	return &sync.Pool{
		New: func() any {
			buffer := make([]byte, size)
			return &buffer
		},
	}
}

// GetBuffer retrieves a buffer from the pool and resets it to full capacity.
// It ensures the returned buffer has at least DefaultBufferSize capacity.
func GetBuffer(pool *sync.Pool) *[]byte {
	buffer := pool.Get().(*[]byte)
	// If the buffer was shrunk (e.g. by internal library behavior), discard it and reallocate.
	// We use DefaultBufferSize (16KB) as the minimum acceptable capacity for any pooled buffer.
	if buffer == nil || cap(*buffer) < DefaultBufferSize {
		newBuf := make([]byte, DefaultBufferSize)
		return &newBuf
	}
	// Reset slice to use full available capacity
	*buffer = (*buffer)[:cap(*buffer)]
	return buffer
}

// PutBuffer returns a buffer to the pool after resetting it
func PutBuffer(pool *sync.Pool, buffer *[]byte) {
	if buffer != nil && cap(*buffer) > 0 {
		// Reset the slice to its full capacity before returning to pool
		*buffer = (*buffer)[:cap(*buffer)]
		pool.Put(buffer)
	}
}

// CopyBufferWithWriteTimeout copies data from src to dst with write timeout
func CopyBufferWithWriteTimeout(
	dst DeadlineWriter,
	src io.Reader,
	buf []byte,
	timeout time.Duration,
) (written int64, err error) {
	if timeout == 0 {
		timeout = DefaultWriteTimeout
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			err = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				break
			}

			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0

				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nw)

			if ew != nil {
				err = ew
				break
			}

			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}

// IsStreamConn 检查连接是否是流式连接（TCP/QUIC），而不是 WebSocket
func IsStreamConn(conn any) bool {
	if conn == nil {
		return false
	}
	typeName := strings.ToLower(fmt.Sprintf("%T", conn))
	return !strings.Contains(typeName, "websocket")
}

// LockedWriter wraps a DeadlineWriter with a mutex to ensure thread-safe writes.
type LockedWriter struct {
	W  DeadlineWriter
	Mu *sync.Mutex
}

func (w *LockedWriter) Write(p []byte) (int, error) {
	w.Mu.Lock()
	n, err := w.W.Write(p)
	w.Mu.Unlock()
	return n, err
}

func (w *LockedWriter) SetWriteDeadline(t time.Time) error {
	w.Mu.Lock()
	err := w.W.SetWriteDeadline(t)
	w.Mu.Unlock()
	return err
}

// LockedConn wraps a net.Conn with a mutex for thread-safe Write operations.
type LockedConn struct {
	net.Conn
	Mu *sync.Mutex
}

func (c *LockedConn) Write(p []byte) (int, error) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.Conn.Write(p)
}

func (c *LockedConn) SetWriteDeadline(t time.Time) error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.Conn.SetWriteDeadline(t)
}
