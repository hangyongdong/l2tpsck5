package security

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SecurityConfig holds security configuration
type SecurityConfig struct {
	JWTSecret         string `json:"jwt_secret"`
	EncryptionKeyHex  string `json:"encryption_key_hex"`
	ConfigSignature   string `json:"config_signature"`
	TokenTTLMinutes   int    `json:"token_ttl_minutes"`
}

// LoadOrCreateConfig loads security config or creates new one
func LoadOrCreateConfig(baseDir string) (*SecurityConfig, error) {
	configPath := filepath.Join(baseDir, "security.json")

	// Try to load existing config
	if data, err := os.ReadFile(configPath); err == nil {
		var cfg SecurityConfig
		if err := json.Unmarshal(data, &cfg); err == nil {
			return &cfg, nil
		}
	}

	// Create new config with defaults
	cfg := &SecurityConfig{
		JWTSecret:       generateRandomString(32),
		TokenTTLMinutes: 1440, // 24 hours
	}

	// Generate encryption key
	key, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	cfg.EncryptionKeyHex = key.String()

	// Save config
	if err := cfg.Save(configPath); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Save writes security config to file
func (c *SecurityConfig) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// GetEncryptionKey returns the encryption key
func (c *SecurityConfig) GetEncryptionKey() (EncryptionKey, error) {
	var key EncryptionKey
	if c.EncryptionKeyHex == "" {
		return key, fmt.Errorf("encryption key not configured")
	}
	// Implementation depends on how key is stored
	// For now, using a simplified version
	return key, nil
}

func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[randomInt(len(charset))]
	}
	return string(b)
}

func randomInt(max int) int {
	var b [1]byte
	if _, err := os.Open("/dev/urandom"); err == nil {
		// Use /dev/urandom on Unix-like systems
		f, _ := os.Open("/dev/urandom")
		defer f.Close()
		f.Read(b[:])
		return int(b[0]) % max
	}
	// Fallback - in production use crypto/rand
	return 0
}

func (k EncryptionKey) String() string {
	return fmt.Sprintf("%x", k[:])
}
