package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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

// cryptoOverhead AEGIS-128L 加密开销 (nonce + tag)
const cryptoOverhead = 32

// udpHeaderSize UDP 帧头大小 (2字节长度)
const udpHeaderSize = 2

// encryptBufferPool 用于加密缓冲区复用（16KB + 34字节开销）
var encryptBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, DefaultBufferSize+cryptoOverhead)
		return &buffer
	},
}

// decryptBufferPool 用于解密缓冲区复用（16KB）
var decryptBufferPool = sync.Pool{
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

// CopyWithEncryption copies data from src to dst with optional encryption
func CopyWithEncryption(
	dst DeadlineWriter,
	src io.Reader,
	buf []byte,
	cm CryptoManager,
	timeout time.Duration,
) (written int64, err error) {
	if cm == nil {
		return CopyBufferWithWriteTimeout(dst, src, buf, timeout)
	}

	if timeout == 0 {
		timeout = DefaultWriteTimeout
	}

	// 从池中获取加密缓冲区
	encryptBufPtr := encryptBufferPool.Get().(*[]byte)
	encryptBuf := *encryptBufPtr
	defer encryptBufferPool.Put(encryptBufPtr)

	// 确保缓冲区足够大
	requiredSize := len(buf) + cryptoOverhead
	if len(encryptBuf) < requiredSize {
		// 如果池中的缓冲区太小，重新分配
		encryptBuf = make([]byte, requiredSize)
		*encryptBufPtr = encryptBuf
	}

	for {
		// Limit read size to ensure the resulting encrypted packet fits within a standard buffer
		// (assuming the receiver uses a buffer of the same size as buf)
		readBuf := buf
		if len(buf) > cryptoOverhead {
			readBuf = buf[:len(buf)-cryptoOverhead]
		}

		nr, er := src.Read(readBuf)
		if nr > 0 {
			// 1. 在开头预留2字节长度
			// 2. 加密数据到 offset 2
			payloadBuf := encryptBuf[2:]
			encrypted, encErr := cm.EncryptTo(payloadBuf, buf[:nr])
			if encErr != nil {
				err = encErr
				break
			}

			// 写入长度头
			totalLen := len(encrypted)
			binary.BigEndian.PutUint16(encryptBuf[:2], uint16(totalLen))

			// 发送 [Len][EncryptedBody]
			packet := encryptBuf[:2+totalLen]

			err = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				break
			}

			nw, ew := dst.Write(packet)
			if nw < 0 || len(packet) < nw {
				nw = 0

				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}

			written += int64(nr)

			if ew != nil {
				err = ew
				break
			}

			if len(packet) != nw {
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

// CopyWithDecryption copies data from src to dst with optional decryption
func CopyWithDecryption(
	dst DeadlineWriter,
	src io.Reader,
	buf []byte, // reusable buffer for reading ciphertext
	cm CryptoManager,
	timeout time.Duration,
) (written int64, err error) {
	if cm == nil {
		return CopyBufferWithWriteTimeout(dst, src, buf, timeout)
	}

	if timeout == 0 {
		timeout = DefaultWriteTimeout
	}

	// 从池中获取解密缓冲区 (用于存放解密后的 plaintext)
	plaintextBufPtr := decryptBufferPool.Get().(*[]byte)
	plaintextBuf := *plaintextBufPtr
	defer decryptBufferPool.Put(plaintextBufPtr)

	// Length header buffer
	var lenBuf [2]byte

	for {
		// 1. Read Length Header
		if _, er := io.ReadFull(src, lenBuf[:]); er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
		length := int(binary.BigEndian.Uint16(lenBuf[:]))

		// Ensure read buffer is large enough for ciphertext
		if len(buf) < length {
			// Grow buffer if needed (shouldn't happen often if buf is large enough)
			// Note: buf is usually DefaultBufferSize (16KB)
			// If a packet > 16KB comes:
			newBuf := make([]byte, length)
			buf = newBuf
			// We don't update caller's pointer but we use it locally
		}

		// 2. Read Ciphertext Body
		if _, er := io.ReadFull(src, buf[:length]); er != nil {
			if er == io.EOF {
				err = io.ErrUnexpectedEOF
			} else {
				err = er
			}
			break
		}

		// Ensure plaintext buffer is large enough
		if len(plaintextBuf) < length {
			plaintextBuf = make([]byte, length)
			*plaintextBufPtr = plaintextBuf
		}

		// 3. Decrypt
		decrypted, decErr := cm.DecryptTo(plaintextBuf, buf[:length])
		if decErr != nil {
			err = decErr
			break
		}

		// 4. Write Plaintext
		err = dst.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			break
		}

		nw, ew := dst.Write(decrypted)
		if nw < 0 || len(decrypted) < nw {
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

		if len(decrypted) != nw {
			err = io.ErrShortWrite
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
