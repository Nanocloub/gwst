package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/aegis-aead/go-libaegis/aegis128l"
	"github.com/aegis-aead/go-libaegis/aegis128x2"
	"github.com/aegis-aead/go-libaegis/aegis128x4"
)

// Algorithm specifies which AEGIS variant to use.
type Algorithm string

const (
	// AlgoAEGIS128L is the original AEGIS-128L algorithm (default).
	AlgoAEGIS128L Algorithm = "aegis-128l"
	// AlgoAEGIS128X2 is AEGIS-128X2, a parallelised 2-lane variant of AEGIS-128L.
	AlgoAEGIS128X2 Algorithm = "aegis-128x2"
	// AlgoAEGIS128X4 is AEGIS-128X4, a parallelised 4-lane variant of AEGIS-128L.
	AlgoAEGIS128X4 Algorithm = "aegis-128x4"
)

const (
	// KeySize key size shared by all supported algorithms (16 bytes)
	KeySize = 16
	// NonceSize nonce size shared by all supported algorithms (16 bytes)
	NonceSize = 16
	// TagSize authentication tag size (16 bytes)
	TagSize = 16
	// MaxOverhead 加密最大开销 (nonce + tag)
	MaxOverhead = NonceSize + TagSize
)

var (
	// ErrInvalidKeySize indicates key is not 16 bytes
	ErrInvalidKeySize = errors.New("invalid key size: must be 16 bytes")
	// ErrInvalidCiphertext indicates ciphertext format is invalid
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	// ErrDecryptionFailed indicates decryption or authentication failed
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrUnknownAlgorithm indicates an unrecognised algorithm name
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
)

// newAEAD returns a fresh cipher.AEAD for the given algorithm and key.
func newAEAD(algo Algorithm, key []byte) (cipher.AEAD, error) {
	switch algo {
	case AlgoAEGIS128L, "":
		return aegis128l.New(key, TagSize)
	case AlgoAEGIS128X2:
		return aegis128x2.New(key, TagSize)
	case AlgoAEGIS128X4:
		return aegis128x4.New(key, TagSize)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownAlgorithm, algo)
	}
}

// Manager handles AEGIS encryption and decryption.
// The concrete algorithm is chosen at construction time.
type Manager struct {
	algo     Algorithm
	aeadPool sync.Pool
	counter  atomic.Uint64 // 用于生成唯一 nonce（计数器部分）
}

// NewManager creates a new crypto manager with AEGIS-128L (default algorithm).
func NewManager(key []byte) (*Manager, error) {
	return NewManagerWithAlgo(key, AlgoAEGIS128L)
}

// NewManagerWithAlgo creates a new crypto manager with the specified AEGIS algorithm.
// algo may be AlgoAEGIS128L, AlgoAEGIS128X2, or AlgoAEGIS128X4.
// An empty string is treated as AlgoAEGIS128L.
func NewManagerWithAlgo(key []byte, algo Algorithm) (*Manager, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	if algo == "" {
		algo = AlgoAEGIS128L
	}

	// Copy key so caller mutations after construction cannot affect pool-allocated
	// AEAD objects: go-libaegis stores a.Key = key (a slice reference, not a copy).
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, key)

	// Probe once to validate the algorithm and CGO availability.
	if _, err := newAEAD(algo, keyCopy); err != nil {
		return nil, err
	}

	m := &Manager{
		algo: algo,
	}
	m.aeadPool.New = func() any {
		aead, _ := newAEAD(algo, keyCopy)
		return aead
	}

	return m, nil
}

// Algo returns the algorithm used by this Manager.
func (m *Manager) Algo() Algorithm { return m.algo }

// Encrypt encrypts plaintext using the configured AEGIS algorithm.
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

// Decrypt decrypts ciphertext using the configured AEGIS algorithm.
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

