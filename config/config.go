package config

import (
	"os"
)

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

// GetGoogleClientID returns Google OAuth Client ID
func GetGoogleClientID() string {
	return os.Getenv("GOOGLE_CLIENT_ID")
}

// GetGoogleClientSecret returns Google OAuth Client Secret
func GetGoogleClientSecret() string {
	return os.Getenv("GOOGLE_CLIENT_SECRET")
}