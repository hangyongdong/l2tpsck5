package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"singbox-webui/internal/handler"
	"singbox-webui/internal/security"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	baseDir := flag.String("dir", ".", "webui base directory")
	flag.Parse()

	absDir, err := filepath.Abs(*baseDir)
	if err != nil {
		log.Fatal(err)
	}

	// Load or create security configuration
	secConfig, err := security.LoadOrCreateConfig(absDir)
	if err != nil {
		log.Fatalf("Failed to load security config: %v", err)
	}

	// Initialize JWT manager
	jwtManager := security.NewJWTManager(secConfig.JWTSecret, time.Duration(secConfig.TokenTTLMinutes)*time.Minute)

	// Initialize auth manager
	authManager := security.NewAuthManager(jwtManager)

	// Create API handler with security
	api, err := handler.NewWithSecurity(absDir, authManager)
	if err != nil {
		log.Fatal(err)
	}
	defer api.Close()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	// Add security headers middleware
	r.Use(security.CORSMiddleware)

	// Public endpoints (no auth required)
	r.Get("/api/license", api.License)
	r.Post("/api/license", api.License)
	r.Get("/api/license/bootstrap", api.License)
	r.Post("/api/license/bootstrap", api.License)
	r.Get("/api/license/check", api.License)
	r.Post("/api/license/check", api.License)
	
	// Login endpoint (no auth required)
	r.Post("/api/auth/login", api.Login)

	// Protected endpoints (auth required)
	r.Group(func(authR chi.Router) {
		authR.Use(security.AuthMiddleware(jwtManager))
		
		authR.Get("/api/version", api.Version)
		authR.Get("/api/stats", api.Stats)
		authR.Get("/api/traffic", api.Traffic)
		authR.Post("/api/action", api.Action)
		authR.Post("/api/ros", api.Ros)
	})

	// Static files
	fileServer := http.FileServer(http.Dir(absDir))
	r.NotFound(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			http.ServeFile(w, req, filepath.Join(absDir, "index.html"))
			return
		}
		fileServer.ServeHTTP(w, req)
	})

	log.Printf("singbox-webui secure listening on %s, baseDir=%s", *addr, absDir)
	log.Printf("Please login at http://localhost:8080 with your credentials")
	if err := http.ListenAndServe(*addr, r); err != nil {
		log.Fatal(err)
	}
}
