package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// SignData creates an HMAC-SHA256 signature for data
func SignData(data []byte, key EncryptionKey) string {
	h := hmac.New(sha256.New, key[:])
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// VerifySignature verifies an HMAC-SHA256 signature
func VerifySignature(data []byte, signature string, key EncryptionKey) bool {
	expected := SignData(data, key)
	return hmac.Equal([]byte(expected), []byte(signature))
}

// ValidateConfigSignature validates config.json integrity
func ValidateConfigSignature(configData []byte, signature string, key EncryptionKey) error {
	if !VerifySignature(configData, signature, key) {
		return fmt.Errorf("config.json signature verification failed")
	}
	return nil
}
