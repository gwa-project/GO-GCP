# PASETO Key Generation Guide

## 🔐 Apa itu PRKEY?

PRKEY adalah **Private Key untuk PASETO v4 encryption** yang digunakan untuk:
- Encrypt/decrypt access tokens
- Encrypt/decrypt refresh tokens
- Secure session management
- Authentication yang stateless

## 🛠️ Cara Generate PASETO Key

### Method 1: Generate Random Key (Recommended)

```bash
cd GO-GCP
go run cmd/keygen/main.go -generate
```

Output contoh:
```
Generated PASETO Key: b0ba5e4e407f44707c04e40733b6ec849ba28e3df0e273abce0efbcff8785876

Add this to your GitHub Actions Secrets:
PRKEY=b0ba5e4e407f44707c04e40733b6ec849ba28e3df0e273abce0efbcff8785876
```

### Method 2: Generate dari Passphrase

```bash
cd GO-GCP
go run cmd/keygen/main.go -passphrase "gwa-project-secure-key-2024"
```

Output:
```
PASETO Key from passphrase: 6777612d70726f6a6563742d7365637572652d6b65792d323032340000000000

Add this to your GitHub Actions Secrets:
PRKEY=6777612d70726f6a6563742d7365637572652d6b65792d323032340000000000
```

### Method 3: Validate Existing Key

```bash
cd GO-GCP
go run cmd/keygen/main.go -validate "your-hex-key-here"
```

## ⚙️ Setup di GitHub Actions

1. **Buka GitHub Repository** → Settings → Secrets and variables → Actions

2. **Add New Secret:**
   - Name: `PRKEY`
   - Value: `b0ba5e4e407f44707c04e40733b6ec849ba28e3df0e273abce0efbcff8785876` (contoh)

3. **Verifikasi** di GitHub Actions environment variables:
   ```
   ✅ GOOGLE_CLIENT_ID
   ✅ GOOGLE_CLIENT_SECRET
   ✅ MONGOSTRING
   ✅ PRKEY  ← (New!)
   ```

## 🔒 Security Requirements

### Key Format:
- **Length:** Exactly 32 bytes (64 hex characters)
- **Format:** Hexadecimal string
- **Algorithm:** PASETO v4 symmetric encryption

### Security Best Practices:
- ✅ Use random generation untuk production
- ✅ Store di GitHub Actions Secrets (encrypted)
- ✅ Never commit key ke repository
- ✅ Rotate key secara berkala
- ✅ Use different keys untuk different environments

## 🧪 Testing Keys

### Quick Test:
```bash
cd GO-GCP
go run cmd/keygen/main.go -info
```

### Full Validation:
```bash
cd GO-GCP
go run cmd/keygen/main.go -validate "your-key-here"
```

### Test dengan Helper Function:
```go
import "github.com/gocroot/helper"

// Test create token
token, err := helper.CreatePasetoToken("user123", 1*time.Hour)
if err != nil {
    log.Fatal("Key tidak valid:", err)
}

// Test verify token
userID, err := helper.VerifyPasetoToken(token)
if err != nil {
    log.Fatal("Verification gagal:", err)
}
```

## 🚀 Production Setup

### Environment Variables Required:
```bash
# Required untuk PASETO
PRKEY=your-32-byte-hex-key

# Required untuk Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Required untuk Database
MONGOSTRING=mongodb+srv://user:pass@cluster.mongodb.net/

# Optional
ENVIRONMENT=production
```

### Key Rotation Strategy:
1. Generate new key
2. Update GitHub Actions secret
3. Deploy aplikasi
4. Old tokens akan expire naturally (1-7 hari)

## ❗ Troubleshooting

### Error: "Invalid key format"
- Key harus 64 hex characters (32 bytes)
- Generate ulang dengan tool ini

### Error: "Key validation failed"
- Key corrupt atau format salah
- Generate key baru

### Error: "Token verification failed"
- PRKEY di production berbeda dengan yang generate token
- Pastikan environment variable benar

## 📖 More Info

- [PASETO Specification](https://paseto.io/)
- [PASETO vs JWT Security](https://auth0.com/blog/paseto-vs-jwt/)
- [GO-GCP Authentication Documentation](./README.md)

---

**Generated Key untuk Testing:**
```
PRKEY=b0ba5e4e407f44707c04e40733b6ec849ba28e3df0e273abce0efbcff8785876
```

⚠️ **Jangan gunakan key di atas untuk production!** Generate key baru dengan `go run cmd/keygen/main.go -generate`