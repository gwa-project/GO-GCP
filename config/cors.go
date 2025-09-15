package config

import (
	"net/http"
)

// AllowedOrigins defines allowed CORS origins
var AllowedOrigins = []string{
	"https://your-domain.com",
	"https://www.your-domain.com",
	"http://localhost:3000",
	"http://localhost:8080",
}

// SetCORS sets CORS headers
func SetCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	// Check if origin is allowed
	for _, allowedOrigin := range AllowedOrigins {
		if origin == allowedOrigin {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			break
		}
	}

	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Login, Hashed")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}