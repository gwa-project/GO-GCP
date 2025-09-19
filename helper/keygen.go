package helper

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	"aidanwoods.dev/go-paseto"
)

// GeneratePasetoKey generates a new PASETO symmetric key (32 bytes)
func GeneratePasetoKey() (string, error) {
	// Generate random 32 bytes for PASETO v4 symmetric key
	keyBytes := make([]byte, 32)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %v", err)
	}

	// Convert to hex string for storage
	return hex.EncodeToString(keyBytes), nil
}

// GeneratePasetoKeyFromPassphrase generates a PASETO key from a passphrase
func GeneratePasetoKeyFromPassphrase(passphrase string) string {
	// Convert passphrase to 32-byte key
	key := make([]byte, 32)
	copy(key, []byte(passphrase))

	// If passphrase is shorter than 32 bytes, pad with zeros
	// If longer, truncate to 32 bytes
	return hex.EncodeToString(key)
}

// ValidatePasetoKey validates if a key can be used for PASETO
func ValidatePasetoKey(keyHex string) error {
	// Decode hex string
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid hex format: %v", err)
	}

	// Check key length (must be 32 bytes for PASETO v4)
	if len(keyBytes) != 32 {
		return fmt.Errorf("key must be exactly 32 bytes, got %d bytes", len(keyBytes))
	}

	// Try to create PASETO symmetric key
	symmetricKey := paseto.NewV4SymmetricKey()
	copy(symmetricKey.ExportBytes(), keyBytes)

	// Test encryption/decryption
	token := paseto.NewToken()
	token.SetIssuer("test")
	token.SetSubject("test")
	token.SetExpiration(time.Now().Add(1 * time.Hour))
	token.SetIssuedAt(time.Now())

	encrypted := token.V4Encrypt(symmetricKey, nil)

	parser := paseto.NewParser()
	_, err = parser.ParseV4Local(symmetricKey, encrypted, nil)
	if err != nil {
		return fmt.Errorf("key validation failed: %v", err)
	}

	return nil
}

// PrintPasetoKeyInfo prints information about generating PASETO keys
func PrintPasetoKeyInfo() {
	fmt.Println("=== PASETO Key Generation Guide ===")
	fmt.Println()
	fmt.Println("PASETO v4 requires a 32-byte (256-bit) symmetric key for encryption.")
	fmt.Println()
	fmt.Println("Option 1: Generate a random key")
	key, err := GeneratePasetoKey()
	if err != nil {
		log.Printf("Error generating key: %v", err)
		return
	}
	fmt.Printf("Random Key: %s\n", key)
	fmt.Println()

	fmt.Println("Option 2: Use a passphrase (will be padded/truncated to 32 bytes)")
	passphraseKey := GeneratePasetoKeyFromPassphrase("gwa-project-secure-key-2024")
	fmt.Printf("Passphrase Key: %s\n", passphraseKey)
	fmt.Println()

	fmt.Println("Add this to your GitHub Actions Secrets as 'PRKEY':")
	fmt.Printf("PRKEY=%s\n", key)
	fmt.Println()
	fmt.Println("=== End Guide ===")
}