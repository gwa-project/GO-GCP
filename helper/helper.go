package helper

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/gocroot/config"
	"golang.org/x/crypto/bcrypt"
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

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword verifies a password against its hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// GoogleTokenInfo represents Google token verification response
type GoogleTokenInfo struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Azp           string `json:"azp"`
	Aud           string `json:"aud"`
	Iat           string `json:"iat"`
	Exp           string `json:"exp"`
	Email         string `json:"email"`
	EmailVerified string `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Locale        string `json:"locale"`
}

// VerifyGoogleToken verifies Google OAuth token
func VerifyGoogleToken(idToken string) (*GoogleTokenInfo, error) {
	url := fmt.Sprintf("https://oauth2.googleapis.com/tokeninfo?id_token=%s", idToken)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid token: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var tokenInfo GoogleTokenInfo
	err = json.Unmarshal(body, &tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &tokenInfo, nil
}

// CreateRefreshToken creates a refresh token
func CreateRefreshToken(userID string) (string, error) {
	// Create refresh token with longer duration (7 days)
	return CreatePasetoToken(userID, 7*24*time.Hour)
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	return len(email) > 0 && len(email) <= 254
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) < 6 {
		return fmt.Errorf("password must be at least 6 characters")
	}
	return nil
}