# 🚀 GO-GCP

Go-based microservice untuk Google Cloud Platform menggunakan Cloud Functions dengan **PASETO Authentication System**

## 🔐 Quick Setup - Generate PASETO Key

**PENTING:** Sebelum deploy, generate PASETO key dulu:

```bash
# Method 1: Generate random 32-byte hex key
openssl rand -hex 32

# Method 2: Manual generation using Go helper functions
# Lihat file helper/keygen.go untuk fungsi GeneratePasetoKey() dan GeneratePasetoKeyFromPassphrase()
```

Copy output ke GitHub Actions Secrets sebagai `PRKEY`.

📖 **[Panduan Lengkap PASETO Key →](./PASETO_KEY_GUIDE.md)**

## ✨ Features

- ✅ **Google OAuth SSO** - Login dengan Google account
- ✅ **Regular Login** - Email + password authentication
- ✅ **PASETO Tokens** - Secure stateless authentication
- ✅ **Password Hashing** - bcrypt security
- ✅ **Token Refresh** - Auto refresh mechanism
- ✅ **MongoDB Integration** - User data storage
- ✅ **CORS Protection** - Cross-origin security

## 📁 Project Structure

```
GO-GCP/
├── main.go                 # Google Cloud Functions entry point
├── go.mod                  # Go module dependencies
├── go.sum                  # Dependency checksums
├── config/                 # Configuration files
│   ├── config.go          # Environment variables
│   ├── cors.go            # CORS configuration
│   └── db.go              # Database connection
├── controller/            # HTTP handlers
│   └── controller.go      # Main API controllers
├── helper/                # Utility functions
│   ├── helper.go          # Authentication helpers
│   └── keygen.go          # PASETO key generation utilities
├── model/                 # Data models
│   └── model.go           # User and auth models
├── route/                 # HTTP routing
│   └── route.go           # URL routing logic
├── README.md              # This file
└── PASETO_KEY_GUIDE.md    # PASETO key setup guide
```

