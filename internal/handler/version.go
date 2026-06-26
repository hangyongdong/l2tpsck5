package handler

import (
	"net/http"
	"time"
)

// Version returns API version without sensitive debug info
func (a *API) Version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"version":    "2.0.0-secure",
		"build_time": time.Now().Format(time.RFC3339),
		// SECURITY: Removed go_version and os_arch to prevent fingerprinting
	})
}
