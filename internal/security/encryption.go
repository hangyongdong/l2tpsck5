package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptionKey represents a 32-byte AES-256 key
type EncryptionKey [32]byte

// GenerateKey creates a new random encryption key
func GenerateKey() (EncryptionKey, error) {
	var key EncryptionKey
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("failed to generate encryption key: %w", err)
	}
	return key, nil
}

// LoadKeyFromBytes converts 32 bytes to EncryptionKey
func LoadKeyFromBytes(b []byte) (EncryptionKey, error) {
	var key EncryptionKey
	if len(b) != 32 {
		return key, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(b))
	}
	copy(key[:], b)
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func Encrypt(key EncryptionKey, plaintext string) (string, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext encrypted with Encrypt
func Decrypt(key EncryptionKey, ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext_data := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext_data, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}
