package helper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/gocroot/config"
)

// GenerateID generates a random ID
func GenerateID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		log.Printf("Error generating ID: %v", err)
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(bytes)
}

// GetCurrentTime returns current timestamp
func GetCurrentTime() time.Time {
	return time.Now()
}

// ResponseSuccess creates a success response
func ResponseSuccess(message string, data interface{}) map[string]interface{} {
	return map[string]interface{}{
		"success":   true,
		"message":   message,
		"data":      data,
		"timestamp": GetCurrentTime(),
	}
}

// ResponseError creates an error response
func ResponseError(message string, code int) map[string]interface{} {
	return map[string]interface{}{
		"success":   false,
		"error":     message,
		"code":      code,
		"timestamp": GetCurrentTime(),
	}
}

// CreatePasetoToken creates a new PASETO token
func CreatePasetoToken(userID string, duration time.Duration) (string, error) {
	privateKey := config.GetPrivateKey()
	if privateKey == "" {
		privateKey = "default-key-32-bytes-long-for-paseto"
	}

	if len(privateKey) < 32 {
		// Pad the key to 32 bytes if it's shorter
		key := make([]byte, 32)
		copy(key, []byte(privateKey))
		privateKey = string(key)
	}

	// Use first 32 bytes and create proper symmetric key
	keyBytes := []byte(privateKey)[:32]
	symmetricKey := paseto.NewV4SymmetricKey()
	copy(symmetricKey.ExportBytes(), keyBytes)

	token := paseto.NewToken()

	// Set claims
	token.SetIssuer("gwa-project")
	token.SetSubject(userID)
	token.SetAudience("go-gcp-api")
	token.SetExpiration(time.Now().Add(duration))
	token.SetNotBefore(time.Now())
	token.SetIssuedAt(time.Now())

	// Add custom claims
	token.Set("user_id", userID)
	token.Set("project", "gwa-project-472118")

	// Encrypt the token
	encrypted := token.V4Encrypt(symmetricKey, nil)
	return encrypted, nil
}

// VerifyPasetoToken verifies a PASETO token
func VerifyPasetoToken(tokenString string) (string, error) {
	privateKey := config.GetPrivateKey()
	if privateKey == "" {
		privateKey = "default-key-32-bytes-long-for-paseto"
	}

	if len(privateKey) < 32 {
		key := make([]byte, 32)
		copy(key, []byte(privateKey))
		privateKey = string(key)
	}

	keyBytes := []byte(privateKey)[:32]
	symmetricKey := paseto.NewV4SymmetricKey()
	copy(symmetricKey.ExportBytes(), keyBytes)

	parser := paseto.NewParser()

	// Decrypt the token
	token, err := parser.ParseV4Local(symmetricKey, tokenString, nil)
	if err != nil {
		return "", err
	}

	// Check if token is expired
	expiration, err := token.GetExpiration()
	if err != nil {
		return "", err
	}
	if time.Now().After(expiration) {
		return "", fmt.Errorf("token has expired")
	}

	// Extract user ID
	userID, err := token.GetString("user_id")
	if err != nil {
		return "", err
	}

	return userID, nil
}

// LogInfo logs an info message
func LogInfo(message string) {
	log.Printf("[INFO] %s", message)
}

// LogError logs an error message
func LogError(message string, err error) {
	if err != nil {
		log.Printf("[ERROR] %s: %v", message, err)
	} else {
		log.Printf("[ERROR] %s", message)
	}
}