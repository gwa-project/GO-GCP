package helper

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"aidanwoods.dev/go-paseto"
	"github.com/gwa-project/GO-GCP/config"
)

// PasetoMaker handles PASETO token creation and validation
type PasetoMaker struct {
	symmetricKey []byte
}

// NewPasetoMaker creates a new PasetoMaker instance
func NewPasetoMaker() (*PasetoMaker, error) {
	privateKey := config.GetPrivateKey()
	if len(privateKey) < 32 {
		// Pad the key to 32 bytes if it's shorter
		key := make([]byte, 32)
		copy(key, []byte(privateKey))
		return &PasetoMaker{symmetricKey: key}, nil
	}

	// Use first 32 bytes if longer
	key := []byte(privateKey)[:32]
	return &PasetoMaker{symmetricKey: key}, nil
}

// CreateToken creates a new PASETO token
func (maker *PasetoMaker) CreateToken(userID string, duration time.Duration) (string, error) {
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
	encrypted := token.V4Encrypt(maker.symmetricKey, nil)
	return encrypted, nil
}

// VerifyToken verifies a PASETO token
func (maker *PasetoMaker) VerifyToken(tokenString string) (*TokenPayload, error) {
	parser := paseto.NewParser()

	// Decrypt the token
	token, err := parser.ParseV4Local(maker.symmetricKey, tokenString, nil)
	if err != nil {
		return nil, err
	}

	// Check if token is expired
	if time.Now().After(token.GetExpiration()) {
		return nil, ErrExpiredToken
	}

	// Check if token is valid yet
	if time.Now().Before(token.GetNotBefore()) {
		return nil, ErrInvalidToken
	}

	// Extract claims
	userID, err := token.GetString("user_id")
	if err != nil {
		return nil, err
	}

	project, _ := token.GetString("project")

	payload := &TokenPayload{
		UserID:    userID,
		Project:   project,
		IssuedAt:  token.GetIssuedAt(),
		ExpiredAt: token.GetExpiration(),
	}

	return payload, nil
}

// TokenPayload represents the payload of a token
type TokenPayload struct {
	UserID    string    `json:"user_id"`
	Project   string    `json:"project"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// Custom errors
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

// GenerateSecureKey generates a secure 32-byte key for PASETO
func GenerateSecureKey() string {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "gwa-project-default-key-32bytes-"
	}
	return hex.EncodeToString(key)
}