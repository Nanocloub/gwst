package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"

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

// nonce 池，复用 nonce 缓冲区减少内存分配
var noncePool = sync.Pool{
	New: func() any {
		buf := make([]byte, NonceSize)
		return &buf
	},
}

// Manager handles AEGIS-128L encryption and decryption
type Manager struct {
	aead cipher.AEAD
	key  []byte
}

// NewManager creates a new crypto manager with AEGIS-128L
func NewManager(key []byte) (*Manager, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	// Use 16-byte tag length
	aead, err := aegis128l.New(key, TagSize)
	if err != nil {
		return nil, err
	}

	cm := &Manager{
		aead: aead,
		key:  key,
	}

	return cm, nil
}

// Encrypt encrypts plaintext using AEGIS-128L
// Returns: nonce + ciphertext + tag
func (m *Manager) Encrypt(plaintext []byte) ([]byte, error) {
	// 从池中获取 nonce 缓冲区
	noncePtr := noncePool.Get().(*[]byte)
	nonce := *noncePtr

	// Generate random nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		// 错误时也要归还缓冲区
		noncePool.Put(noncePtr)
		return nil, err
	}

	// 创建结果缓冲区，包含 nonce + ciphertext + tag
	// 使用 make 而不是池化，避免数据竞态
	resultBuf := make([]byte, 0, NonceSize+len(plaintext)+TagSize)
	resultBuf = append(resultBuf, nonce...)

	// 在结果缓冲区中加密（从第 NonceSize 个位置开始）
	ciphertext := m.aead.Seal(resultBuf, nonce, plaintext, nil)

	// 立即归还 nonce 缓冲区，不等待函数返回
	noncePool.Put(noncePtr)

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
	plaintext, err := m.aead.Open(nil, nonce, ciphertext[NonceSize:], nil)
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

	// 从池中获取 nonce 缓冲区
	noncePtr := noncePool.Get().(*[]byte)
	nonce := *noncePtr

	// Generate random nonce
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		noncePool.Put(noncePtr)
		return nil, err
	}

	// 将 nonce 复制到目标缓冲区
	copy(dst[:NonceSize], nonce)

	// 在目标缓冲区中加密（从第 NonceSize 个位置开始）
	// 注意：使用 dst[:NonceSize] 而不是 dst[:NonceSize:NonceSize] 以允许 append 利用后续容量
	ciphertext := m.aead.Seal(dst[:NonceSize], nonce, plaintext, nil)

	// 立即归还 nonce 缓冲区
	noncePool.Put(noncePtr)

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
	plaintext, err := m.aead.Open(dst[:0], nonce, ciphertext[NonceSize:], nil)
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
