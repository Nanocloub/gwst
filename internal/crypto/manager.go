package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/aegis-aead/go-libaegis/aegis128l"
)

const (
	// KeySize AEGIS-128L key size (16 bytes)
	KeySize = 16
	// NonceSize AEGIS-128L nonce size (16 bytes)
	NonceSize = 16
	// TagSize AEGIS-128L authentication tag size (16 bytes)
	TagSize = 16
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
	// Generate random nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt: seal appends the ciphertext and tag to nonce
	ciphertext := m.aead.Seal(nonce, nonce, plaintext, nil)

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

// GenerateKey generates a random AEGIS-128L key
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}
