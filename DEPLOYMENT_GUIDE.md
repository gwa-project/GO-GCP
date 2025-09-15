# 🚀 GO-GCP Deployment Guide

Panduan lengkap untuk deployment aplikasi GO-GCP ke Google Cloud Platform berdasarkan struktur infrastruktur domyikado-main.

## 📋 Prerequisites

### 1. Google Cloud Setup
```bash
# Install Google Cloud SDK
# Download dari: https://cloud.google.com/sdk/docs/install

# Login ke Google Cloud
gcloud auth login

# Set project yang akan digunakan
gcloud config set project gwa-project-472118

# Enable required APIs
gcloud services enable cloudfunctions.googleapis.com
gcloud services enable cloudbuild.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

### 2. Service Account Setup
```bash
# Create service account
gcloud iam service-accounts create go-gcp-deployer \
    --description="Service account for GO-GCP deployment" \
    --display-name="GO-GCP Deployer"

# Grant required roles
gcloud projects add-iam-policy-binding gwa-project-472118 \
    --member="serviceAccount:go-gcp-deployer@gwa-project-472118.iam.gserviceaccount.com" \
    --role="roles/cloudfunctions.developer"

gcloud projects add-iam-policy-binding gwa-project-472118 \
    --member="serviceAccount:go-gcp-deployer@gwa-project-472118.iam.gserviceaccount.com" \
    --role="roles/artifactregistry.admin"

gcloud projects add-iam-policy-binding gwa-project-472118 \
    --member="serviceAccount:go-gcp-deployer@gwa-project-472118.iam.gserviceaccount.com" \
    --role="roles/logging.viewer"

# Create and download service account key
gcloud iam service-accounts keys create service-account-key.json \
    --iam-account=go-gcp-deployer@gwa-project-472118.iam.gserviceaccount.com
```

## 🛠 Local Development

### 1. Setup Environment
```bash
# Clone repository
git clone https://github.com/your-username/go-gcp.git
cd go-gcp

# Copy environment template
cp .env.example .env

# Edit .env dengan konfigurasi Anda
nano .env
```

### 2. Install Dependencies
```bash
# Initialize Go modules
go mod tidy

# Download dependencies
go mod download
```

### 3. Run Local Development Server
```bash
# Run local server
go run ./run/main.go

# Server akan berjalan di http://localhost:8080
```

### 4. Test Endpoints
```bash
# Health check
curl http://localhost:8080/health

# Home endpoint
curl http://localhost:8080/

# API endpoints
curl http://localhost:8080/api/users
```

## ☁️ Cloud Deployment

### Method 1: Manual Deployment via CLI

```bash
# Deploy ke Cloud Functions
gcloud functions deploy go-gcp-function \
  --region=asia-southeast2 \
  --source=. \
  --entry-point=WebHook \
  --runtime=go122 \
  --trigger=http \
  --allow-unauthenticated \
  --timeout=540s \
  --memory=256MB \
  --set-env-vars MONGOSTRING='your-mongo-connection-string',PRKEY='your-private-key',ENVIRONMENT='production'
```

### Method 2: GitHub Actions (Automated)

1. **Setup GitHub Secrets:**
   - Go to repository Settings > Secrets and variables > Actions
   - Add secrets (sesuai dengan yang sudah ada di repository Anda):
     ```
     GOOGLE_CREDENTIALS: [isi dengan content service-account-key.json]
     MONGOSTRING: mongodb+srv://username:password@cluster.mongodb.net/database
     PRKEY: your-private-key
     ```

2. **Deploy via GitHub Actions:**
   ```bash
   # Push ke main branch akan trigger deployment otomatis
   git add .
   git commit -m "Deploy to production"
   git push origin main
   ```

3. **Manual Trigger:**
   - Go to repository > Actions tab
   - Select "Deploy to Google Cloud Functions"
   - Click "Run workflow"

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Example |
|----------|-------------|----------|---------|
| `MONGOSTRING` | MongoDB connection string | Yes | `mongodb+srv://user:pass@cluster.mongodb.net/db` |
| `PRKEY` | Private key for authentication | Yes | `your-secret-key` |
| `ENVIRONMENT` | Application environment | No | `production` |
| `PORT` | Server port (local only) | No | `8080` |

### CORS Configuration

Edit `config/cors.go` untuk mengatur allowed origins:

```go
var AllowedOrigins = []string{
    "https://your-domain.com",
    "https://www.your-domain.com",
    "http://localhost:3000",
    "http://localhost:8080",
}
```

## 🗄 Database Setup (MongoDB)

### 1. MongoDB Atlas Setup
```bash
# 1. Buat cluster di MongoDB Atlas
# 2. Create database user
# 3. Whitelist IP addresses (atau gunakan 0.0.0.0/0 untuk semua IP)
# 4. Get connection string
```

### 2. Database Configuration
```go
// config/db.go sudah dikonfigurasi untuk:
Database = client.Database("gogcp") // Ganti nama database sesuai kebutuhan
```

## 📡 API Endpoints

### Available Endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home page |
| GET | `/health` | Health check |
| GET | `/api/users` | Get all users |
| POST | `/api/users` | Create new user |

### Example Usage:

```bash
# Get function URL after deployment
FUNCTION_URL=$(gcloud functions describe go-gcp-function --region=asia-southeast2 --format="value(serviceConfig.uri)")

# Test deployed function
curl "$FUNCTION_URL/health"
curl "$FUNCTION_URL/api/users"

# Create user
curl -X POST "$FUNCTION_URL/api/users" \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com"}'
```

## 🔍 Monitoring & Logging

### View Logs
```bash
# Cloud Function logs
gcloud functions logs read go-gcp-function --region=asia-southeast2

# Real-time logs
gcloud functions logs tail go-gcp-function --region=asia-southeast2
```

### Monitoring
- Go to Google Cloud Console > Cloud Functions
- Click on your function name
- View metrics, logs, and performance data

## 🚨 Troubleshooting

### Common Issues:

1. **Deployment Failed - Authentication Error**
   ```bash
   # Check authentication
   gcloud auth list
   gcloud config list
   ```

2. **Function Timeout**
   ```bash
   # Increase timeout
   gcloud functions deploy go-gcp-function --timeout=540s
   ```

3. **Environment Variables Not Set**
   ```bash
   # Update environment variables
   gcloud functions deploy go-gcp-function \
     --update-env-vars MONGOSTRING='new-value'
   ```

4. **CORS Issues**
   - Check `config/cors.go`
   - Add your frontend domain to AllowedOrigins

### Debug Commands:
```bash
# Get function details
gcloud functions describe go-gcp-function --region=asia-southeast2

# Get function URL
gcloud functions describe go-gcp-function --region=asia-southeast2 --format="value(serviceConfig.uri)"

# Delete function (if needed)
gcloud functions delete go-gcp-function --region=asia-southeast2
```

## 📦 Project Structure

```
GO-GCP/
├── .github/workflows/          # GitHub Actions CI/CD
│   └── deploy.yml             # Deployment workflow
├── config/                    # Configuration management
│   ├── config.go             # Environment variables
│   ├── cors.go               # CORS settings
│   └── db.go                 # Database connection
├── controller/               # HTTP endpoint handlers
│   └── controller.go         # Request handlers
├── helper/                   # Utility functions
│   └── helper.go             # Helper functions
├── model/                    # Data models
│   └── model.go              # Data structures
├── route/                    # URL routing
│   └── route.go              # Route handlers
├── run/                      # Local development
│   └── main.go               # Local server
├── .env.example              # Environment template
├── .gcloudignore            # GCP deployment exclusions
├── .gitignore               # Git exclusions
├── go.mod                   # Go module dependencies
├── main.go                  # Cloud Function entry point
└── DEPLOYMENT_GUIDE.md      # This guide
```

## 🎯 Next Steps

1. **Customize Application:**
   - Edit controllers untuk business logic Anda
   - Add database models sesuai kebutuhan
   - Implement authentication jika diperlukan

2. **Add More Features:**
   - Add middleware untuk logging/authentication
   - Implement rate limiting
   - Add validation untuk input data

3. **Production Optimization:**
   - Setup monitoring dan alerting
   - Implement caching strategy
   - Add load balancing jika diperlukan

---

**🎉 Selamat! Aplikasi GO-GCP Anda sudah siap untuk production deployment di Google Cloud Platform!**