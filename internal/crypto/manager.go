package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"github.com/aegis-aead/go-libaegis/aegis128l"
)

const (
	// KeySize AEGIS-128L key size (16 bytes)
	KeySize = 16
	// NonceSize AEGIS-128L nonce size (16 bytes)
	NonceSize = 16
	// TagSize AEGIS-128L authentication tag size (16 bytes)
	TagSize = 16
	// MaxOverhead 加密最大开销 (nonce + tag)
	MaxOverhead = NonceSize + TagSize
)

var (
	// ErrInvalidKeySize indicates key is not 16 bytes
	ErrInvalidKeySize = errors.New("invalid key size for AEGIS-128L")
	// ErrInvalidCiphertext indicates ciphertext format is invalid
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	// ErrDecryptionFailed indicates decryption or authentication failed
	ErrDecryptionFailed = errors.New("decryption failed")
)

// Manager handles AEGIS-128L encryption and decryption
type Manager struct {
	key      []byte
	aeadPool sync.Pool
	counter  atomic.Uint64 // 用于生成唯一 nonce（计数器部分）
}

// NewManager creates a new crypto manager with AEGIS-128L
func NewManager(key []byte) (*Manager, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Test creating one to ensure key/tag compatibility
	if _, err := aegis128l.New(key, TagSize); err != nil {
		return nil, err
	}

	m := &Manager{
		key: key,
	}
	m.aeadPool.New = func() any {
		aead, _ := aegis128l.New(key, TagSize)
		return aead
	}

	return m, nil
}

// Encrypt encrypts plaintext using AEGIS-128L
// Returns: nonce + ciphertext + tag
func (m *Manager) Encrypt(plaintext []byte) ([]byte, error) {
	// 使用栈变量生成 nonce，避免堆分配
	var nonce [NonceSize]byte
	count := m.counter.Add(1)
	binary.BigEndian.PutUint64(nonce[:8], count)
	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nil, err
	}

	// 创建结果缓冲区，包含 nonce + ciphertext + tag
	resultBuf := make([]byte, NonceSize, NonceSize+len(plaintext)+TagSize)
	copy(resultBuf, nonce[:])

	aead := m.aeadPool.Get().(cipher.AEAD)
	ciphertext := aead.Seal(resultBuf, nonce[:], plaintext, nil)
	m.aeadPool.Put(aead)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AEGIS-128L
// Expects: nonce + ciphertext + tag
func (m *Manager) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract nonce from the beginning
	nonce := ciphertext[:NonceSize]

	// Decrypt and verify
	aead := m.aeadPool.Get().(cipher.AEAD)
	plaintext, err := aead.Open(nil, nonce, ciphertext[NonceSize:], nil)
	m.aeadPool.Put(aead)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// EncryptTo 加密数据到指定缓冲区，减少内存分配
// dst 必须有足够空间: NonceSize + len(plaintext) + TagSize
// 返回加密后的数据切片（包含 nonce + ciphertext + tag）
func (m *Manager) EncryptTo(dst, plaintext []byte) ([]byte, error) {
	requiredSize := NonceSize + len(plaintext) + TagSize
	if len(dst) < requiredSize {
		return nil, errors.New("destination buffer too small")
	}

	// 使用栈变量生成 nonce，避免堆分配
	var nonce [NonceSize]byte
	count := m.counter.Add(1)
	binary.BigEndian.PutUint64(nonce[:8], count)
	if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
		return nil, err
	}

	// 将 nonce 复制到目标缓冲区
	copy(dst[:NonceSize], nonce[:])

	// 在目标缓冲区中加密（从第 NonceSize 个位置开始）
	aead := m.aeadPool.Get().(cipher.AEAD)
	ciphertext := aead.Seal(dst[:NonceSize], nonce[:], plaintext, nil)
	m.aeadPool.Put(aead)

	return ciphertext, nil
}

// DecryptTo 解密数据到指定缓冲区，减少内存分配
// dst 必须有足够空间: len(ciphertext) - NonceSize - TagSize
// 返回解密后的数据切片
func (m *Manager) DecryptTo(dst, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+TagSize {
		return nil, ErrInvalidCiphertext
	}

	plaintextLen := len(ciphertext) - NonceSize - TagSize
	if len(dst) < plaintextLen {
		return nil, errors.New("destination buffer too small")
	}

	// Extract nonce from the beginning
	nonce := ciphertext[:NonceSize]

	// Decrypt and verify
	aead := m.aeadPool.Get().(cipher.AEAD)
	plaintext, err := aead.Open(dst[:0], nonce, ciphertext[NonceSize:], nil)
	m.aeadPool.Put(aead)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a random AEGIS-128L key
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

