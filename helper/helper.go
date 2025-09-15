package helper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"
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

// ValidateEmail validates email format (simple validation)
func ValidateEmail(email string) bool {
	// Simple email validation - you might want to use a proper regex
	return len(email) > 3 && len(email) < 254 &&
		   fmt.Sprintf("%s", email) != "" &&
		   len(email) > 0
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