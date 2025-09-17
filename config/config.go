package config

import (
	"context"
	"os"

	"github.com/gocroot/model"
	"go.mongodb.org/mongo-driver/bson"
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

// GetGoogleClientID returns Google OAuth Client ID from database
func GetGoogleClientID() string {
	config := getConfigFromDB()
	if config != nil && config.GoogleClientID != "" {
		return config.GoogleClientID
	}
	// Fallback to environment variable
	return os.Getenv("GOOGLE_CLIENT_ID")
}

// GetGoogleClientSecret returns Google OAuth Client Secret from database
func GetGoogleClientSecret() string {
	config := getConfigFromDB()
	if config != nil && config.GoogleClientSecret != "" {
		return config.GoogleClientSecret
	}
	// Fallback to environment variable
	return os.Getenv("GOOGLE_CLIENT_SECRET")
}

// getConfigFromDB retrieves config from database
func getConfigFromDB() *model.Config {
	collection := GetCollection("config")
	if collection == nil {
		return nil
	}

	var config model.Config
	err := collection.FindOne(context.Background(), bson.M{}).Decode(&config)
	if err != nil {
		return nil
	}
	return &config
}

// GetConfigForAPI returns config data safe for API response
func GetConfigForAPI() map[string]interface{} {
	config := getConfigFromDB()
	if config != nil {
		return map[string]interface{}{
			"google_client_id": config.GoogleClientID,
			"app_name":         config.AppName,
			"app_version":      config.AppVersion,
			"environment":      config.Environment,
		}
	}

	// Fallback to environment variables
	return map[string]interface{}{
		"google_client_id": os.Getenv("GOOGLE_CLIENT_ID"),
		"app_name":         "GWA Project",
		"app_version":      "1.0.0",
		"environment":      GetEnvironment(),
	}
}