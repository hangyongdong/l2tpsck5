package security

import (
	"crypto/subtle"
	"fmt"
)

// AuthManager handles authentication
type AuthManager struct {
	jwtManager *JWTManager
	Users     map[string]string // username -> password hash
}

// NewAuthManager creates a new auth manager
func NewAuthManager(jwtManager *JWTManager) *AuthManager {
	return &AuthManager{
		jwtManager: jwtManager,
		Users:     make(map[string]string),
	}
}

// RegisterUser registers a new user with password
func (a *AuthManager) RegisterUser(username, password string) error {
	if username == "" || password == "" {
		return fmt.Errorf("username and password cannot be empty")
	}

	hash := hashPassword(password)
	a.Users[username] = hash
	return nil
}

// AuthenticateUser authenticates a user and returns a token
func (a *AuthManager) AuthenticateUser(username, password string) (string, error) {
	if username == "" || password == "" {
		return "", fmt.Errorf("invalid credentials")
	}

	hash, exists := a.Users[username]
	if !exists {
		return "", fmt.Errorf("invalid credentials")
	}

	if !verifyPassword(password, hash) {
		return "", fmt.Errorf("invalid credentials")
	}

	return a.jwtManager.GenerateToken(username, "admin")
}

// VerifyToken verifies a token
func (a *AuthManager) VerifyToken(token string) (*Claims, error) {
	return a.jwtManager.ValidateToken(token)
}

func hashPassword(password string) string {
	// In production, use bcrypt or argon2
	// For now, using simple hash for demonstration
	return fmt.Sprintf("%x", password)
}

func verifyPassword(password, hash string) bool {
	return subtle.ConstantTimeCompare([]byte(hash), []byte(fmt.Sprintf("%x", password))) == 1
}
