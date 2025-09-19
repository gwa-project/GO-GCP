package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gocroot/helper"
)

func main() {
	var (
		generate   = flag.Bool("generate", false, "Generate a new random PASETO key")
		passphrase = flag.String("passphrase", "", "Generate key from passphrase")
		validate   = flag.String("validate", "", "Validate existing key (hex format)")
		info       = flag.Bool("info", false, "Show PASETO key information")
	)
	flag.Parse()

	if *info {
		helper.PrintPasetoKeyInfo()
		return
	}

	if *generate {
		key, err := helper.GeneratePasetoKey()
		if err != nil {
			fmt.Printf("Error generating key: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated PASETO Key: %s\n", key)
		fmt.Println("\nAdd this to your GitHub Actions Secrets:")
		fmt.Printf("PRKEY=%s\n", key)
		return
	}

	if *passphrase != "" {
		key := helper.GeneratePasetoKeyFromPassphrase(*passphrase)
		fmt.Printf("PASETO Key from passphrase: %s\n", key)
		fmt.Println("\nAdd this to your GitHub Actions Secrets:")
		fmt.Printf("PRKEY=%s\n", key)
		return
	}

	if *validate != "" {
		err := helper.ValidatePasetoKey(*validate)
		if err != nil {
			fmt.Printf("Key validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ Key is valid!")
		return
	}

	// Default: show usage
	fmt.Println("PASETO Key Generator for GWA Project")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  go run cmd/keygen/main.go -generate                    # Generate random key")
	fmt.Println("  go run cmd/keygen/main.go -passphrase \"your-phrase\"   # Generate from passphrase")
	fmt.Println("  go run cmd/keygen/main.go -validate \"hex-key\"         # Validate existing key")
	fmt.Println("  go run cmd/keygen/main.go -info                        # Show detailed info")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  go run cmd/keygen/main.go -generate")
	fmt.Println("  go run cmd/keygen/main.go -passphrase \"gwa-project-secure-2024\"")
	fmt.Println()
}