package handler

import (
	"encoding/json"
	"net/http"

	"singbox-webui/internal/security"
)

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Status string `json:"status"`
	Token  string `json:"token,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Login handles user login and returns JWT token
func (a *API) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"status": "error",
			"error":  "method not allowed",
		})
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "error",
			"error":  "invalid request body",
		})
		return
	}

	// Verify credentials using auth manager
	token, err := a.authManager.AuthenticateUser(req.Username, req.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"status": "error",
			"error":  "invalid credentials",
		})
		return
	}

	writeJSON(w, http.StatusOK, LoginResponse{
		Status: "success",
		Token:  token,
	})
}
