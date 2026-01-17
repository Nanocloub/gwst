package compat

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"time"

	"github.com/aegis-aead/go-libaegis/aegis128l"
)

const (
	// AEGIS-128L key size (16 bytes)
	AegisKeySize = 16
	// AEGIS-128L nonce size (16 bytes)
	AegisNonceSize = 16
	// AEGIS-128L authentication tag size (16 bytes)
	AegisTagSize = 16
)

var (
	ErrInvalidKeySize   = errors.New("invalid key size for AEGIS-128L")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// deadlineWriter is an interface for writers that support write deadlines
type deadlineWriter interface {
	io.Writer
	SetWriteDeadline(time.Time) error
}

// CryptoManager handles AEGIS-128L encryption and decryption
type CryptoManager struct {
	aead cipher.AEAD
	key  []byte
}

// NewCryptoManager creates a new crypto manager with AEGIS-128L
func NewCryptoManager(key []byte) (*CryptoManager, error) {
	if len(key) != AegisKeySize {
		return nil, ErrInvalidKeySize
	}

	// Use 16-byte tag length
	aead, err := aegis128l.New(key, AegisTagSize)
	if err != nil {
		return nil, err
	}

	cm := &CryptoManager{
		aead: aead,
		key:  key,
	}

	return cm, nil
}

// Encrypt encrypts plaintext using AEGIS-128L
// Returns: nonce + ciphertext + tag
func (cm *CryptoManager) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, AegisNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt: seal appends the ciphertext and tag to nonce
	ciphertext := cm.aead.Seal(nonce, nonce, plaintext, nil)

	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AEGIS-128L
// Expects: nonce + ciphertext + tag
func (cm *CryptoManager) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < AegisNonceSize+AegisTagSize {
		return nil, ErrInvalidCiphertext
	}

	// Extract nonce from the beginning
	nonce := ciphertext[:AegisNonceSize]
	
	// Decrypt and verify
	plaintext, err := cm.aead.Open(nil, nonce, ciphertext[AegisNonceSize:], nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// GenerateKey generates a random AEGIS-128L key
func GenerateKey() ([]byte, error) {
	key := make([]byte, AegisKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
