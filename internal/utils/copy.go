package utils

import (
	"errors"
	"io"
	"sync"
	"time"
)

const (
	DefaultWriteTimeout = 15 * time.Second
	// DefaultBufferSize 默认缓冲区大小 16KB
	DefaultBufferSize = 16 * 1024
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

// encryptBufferPool 用于加密缓冲区复用（16KB + 32字节开销）
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

// GetBuffer retrieves a buffer from the pool and resets it to full capacity
func GetBuffer(pool *sync.Pool) *[]byte {
	buffer := pool.Get().(*[]byte)
	// Reset slice to use full capacity
	if buffer != nil && cap(*buffer) > 0 {
		*buffer = (*buffer)[:cap(*buffer)]
	}
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
		nr, er := src.Read(buf)
		if nr > 0 {
			// 使用零分配 API 加密数据
			encrypted, encErr := cm.EncryptTo(encryptBuf, buf[:nr])
			if encErr != nil {
				err = encErr
				break
			}

			err = dst.SetWriteDeadline(time.Now().Add(timeout))
			if err != nil {
				break
			}

			nw, ew := dst.Write(encrypted)
			if nw < 0 || len(encrypted) < nw {
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

			if len(encrypted) != nw {
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

	// 从池中获取解密缓冲区
	decryptBufPtr := decryptBufferPool.Get().(*[]byte)
	decryptBuf := *decryptBufPtr
	defer decryptBufferPool.Put(decryptBufPtr)

	// 确保缓冲区足够大
	if len(decryptBuf) < len(buf) {
		// 如果池中的缓冲区太小，重新分配
		decryptBuf = make([]byte, len(buf))
		*decryptBufPtr = decryptBuf
	}

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// 使用零分配 API 解密数据
			decrypted, decErr := cm.DecryptTo(decryptBuf, buf[:nr])
			if decErr != nil {
				err = decErr
				break
			}

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

		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}

	return written, err
}
