# 🚀 GO-GCP

Go-based microservice untuk Google Cloud Platform menggunakan Cloud Functions, terinspirasi dari arsitektur domyikado-main.

## ✨ Features

- **Cloud Functions Gen 2** - Serverless deployment di Google Cloud
- **MongoDB Integration** - Database connection dengan MongoDB Atlas
- **Clean Architecture** - Struktur folder yang terorganisir dengan baik
- **CORS Support** - Cross-origin request handling
- **CI/CD Pipeline** - Automated deployment dengan GitHub Actions
- **Local Development** - Development server untuk testing lokal
- **Environment Configuration** - Flexible environment variable management

## 🏗 Project Structure

```
GO-GCP/
├── .github/workflows/    # CI/CD configurations
├── config/              # Configuration management
├── controller/          # HTTP handlers
├── helper/             # Utility functions
├── model/              # Data models
├── route/              # URL routing
├── run/                # Local development server
├── main.go             # Cloud Function entry point
└── go.mod              # Dependencies
```

## 🚀 Quick Start

### Local Development

```bash
# 1. Clone repository
git clone https://github.com/gwa-project/GO-GCP.git
cd GO-GCP

# 2. Setup environment
cp .env.example .env
# Edit .env dengan konfigurasi Anda

# 3. Install dependencies
go mod tidy

# 4. Run local server
go run ./run/main.go
```

### Cloud Deployment

Lihat [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) untuk panduan lengkap deployment ke Google Cloud Platform.

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/health` | Health check |
| GET | `/api/users` | Get all users |
| POST | `/api/users` | Create new user |

## 🛠 Technology Stack

- **Language:** Go 1.22
- **Cloud Platform:** Google Cloud Functions Gen 2
- **Database:** MongoDB Atlas
- **CI/CD:** GitHub Actions
- **Authentication:** CORS + Environment variables

## 📚 Documentation

- [Deployment Guide](DEPLOYMENT_GUIDE.md) - Panduan lengkap deployment
- [API Documentation](docs/api.md) - API endpoint documentation (coming soon)

## 🤝 Contributing

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
