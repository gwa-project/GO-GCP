package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
)

func main() {
	fmt.Println("🔑 PASETO Private Key Generator")
	fmt.Println("================================")

	// Generate secure 32-byte key for PASETO v4.local
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		log.Fatal("Failed to generate random key:", err)
	}

	// Convert to hex string
	hexKey := hex.EncodeToString(key)

	fmt.Printf("✅ Generated 32-byte PASETO key:\n")
	fmt.Printf("Raw Hex: %s\n", hexKey)
	fmt.Printf("Length: %d bytes\n", len(key))
	fmt.Println()

	fmt.Println("📋 For GitHub Secrets:")
	fmt.Printf("PRKEY=%s\n", hexKey)
	fmt.Println()

	fmt.Println("🔒 This key is used for:")
	fmt.Println("- PASETO v4.local token encryption/decryption")
	fmt.Println("- Secure by default (no algorithm confusion)")
	fmt.Println("- Perfect for authentication tokens")
	fmt.Println()

	fmt.Println("⚠️  IMPORTANT:")
	fmt.Println("- Keep this key SECRET")
	fmt.Println("- Don't share or commit to repository")
	fmt.Println("- Use only in GitHub Secrets or environment variables")
}