package config

import (
	"os"
)

// Configuration holds all environment variables
type Config struct {
	MongoString  string
	PrivateKey   string
	Environment  string
}

// LoadConfig loads environment variables
func LoadConfig() *Config {
	return &Config{
		MongoString:  os.Getenv("MONGOSTRING"),
		PrivateKey:   os.Getenv("PRKEY"),
		Environment:  getEnv("ENVIRONMENT", "production"),
	}
}

// getEnv gets environment variable with default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetMongoString returns MongoDB connection string
func GetMongoString() string {
	return os.Getenv("MONGOSTRING")
}

// GetPrivateKey returns private key
func GetPrivateKey() string {
	return os.Getenv("PRKEY")
}

