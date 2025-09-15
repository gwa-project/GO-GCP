package config

import (
	"net/http"
	"os"
)

// AllowedOrigins defines allowed CORS origins
var AllowedOrigins = []string{
	"https://gwa-project.vercel.app",
	"https://www.gwa-project.vercel.app",
	"http://localhost:3000",
	"http://localhost:8080",
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

// SetEnv sets environment variables
func SetEnv() {
	// This function can be used to set default environment variables
	// For now, we'll just ensure required vars are available
}

// GetMongoString returns MongoDB connection string
func GetMongoString() string {
	return os.Getenv("MONGOSTRING")
}

// GetPrivateKey returns private key
func GetPrivateKey() string {
	return os.Getenv("PRKEY")
}

// GetEnvironment returns current environment
func GetEnvironment() string {
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		return "development"
	}
	return env
}