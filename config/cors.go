package config

import (
	"net/http"
)

// AllowedOrigins defines allowed CORS origins
var AllowedOrigins = []string{
	"https://gilarya.my.id",
	"https://www.gilarya.my.id",
	"https://dashboard.gilarya.my.id",
	"https://gwa-project.vercel.app",
	"https://www.gwa-project.vercel.app",
	"http://localhost:3000",
	"http://localhost:8080",
	"http://localhost:5000",
	"http://localhost:5500",
	"http://127.0.0.1:5500",
	"http://127.0.0.1:8080",
	"file://",
	"https://chatgpl.do.my.id",
	"https://do.my.id",
}

// SetAccessControlHeaders sets CORS headers and handles preflight
func SetAccessControlHeaders(w http.ResponseWriter, r *http.Request) bool {
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

	// Handle preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}