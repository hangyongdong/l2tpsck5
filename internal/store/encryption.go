package store

import (
	"fmt"
	"os"
	"path/filepath"

	"singbox-webui/internal/security"
)

// EncryptedPasswordManager manages encrypted password storage
type EncryptedPasswordManager struct {
	baseDir string
	key     security.EncryptionKey
}

// NewEncryptedPasswordManager creates a new manager
func NewEncryptedPasswordManager(baseDir string, key security.EncryptionKey) *EncryptedPasswordManager {
	return &EncryptedPasswordManager{
		baseDir: baseDir,
		key:     key,
	}
}

// EncryptPassword encrypts a password
func (m *EncryptedPasswordManager) EncryptPassword(password string) (string, error) {
	return security.Encrypt(m.key, password)
}

// DecryptPassword decrypts a password
func (m *EncryptedPasswordManager) DecryptPassword(encryptedPassword string) (string, error) {
	return security.Decrypt(m.key, encryptedPassword)
}

// SaveEncryptedPassword saves an encrypted password to file
func (m *EncryptedPasswordManager) SaveEncryptedPassword(key string, password string) error {
	encrypted, err := m.EncryptPassword(password)
	if err != nil {
		return err
	}

	path := filepath.Join(m.baseDir, key+".enc")
	return os.WriteFile(path, []byte(encrypted), 0o600)
}

// LoadEncryptedPassword loads and decrypts a password from file
func (m *EncryptedPasswordManager) LoadEncryptedPassword(key string) (string, error) {
	path := filepath.Join(m.baseDir, key+".enc")
	encrypted, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("password not found")
		}
		return "", err
	}

	return m.DecryptPassword(string(encrypted))
}
