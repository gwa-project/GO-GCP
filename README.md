# 🚀 GO-GCP

Go-based microservice untuk Google Cloud Platform menggunakan Cloud Functions dengan **PASETO Authentication System**

## 🔐 Quick Setup - Generate PASETO Key

**PENTING:** Sebelum deploy, generate PASETO key dulu:

```bash
cd GO-GCP
go run cmd/keygen/main.go -generate
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

