# 🚀 Panduan Deploy GO-GCP ke Google Cloud Platform

## 📋 Yang Anda Butuhkan

Berdasarkan secrets yang sudah ada di GitHub repository Anda:
- ✅ `GOOGLE_CREDENTIALS`
- ✅ `MONGOSTRING`
- ✅ `PRKEY`

## 🎯 Cara Deploy

### Method 1: GitHub Actions (OTOMATIS) - **RECOMMENDED**

1. **Push ke GitHub repository:**
   ```bash
   cd GO-GCP
   git add .
   git commit -m "Deploy to GCP"
   git push origin main
   ```

2. **GitHub Actions akan otomatis:**
   - Build aplikasi Go
   - Deploy ke Cloud Functions
   - Set environment variables dari secrets
   - Memberikan URL function yang bisa diakses

3. **Cek status deployment:**
   - Go to: https://github.com/gwa-project/GO-GCP/actions
   - Lihat workflow "Deploy to Google Cloud Functions"
   - Tunggu sampai selesai (✅ hijau)

### Method 2: Manual via CLI

```bash
# 1. Login ke Google Cloud
gcloud auth login

# 2. Set project
gcloud config set project gwa-project-472118

# 3. Deploy function
gcloud functions deploy go-gcp-function \
  --region=asia-southeast2 \
  --source=. \
  --entry-point=WebHook \
  --runtime=go122 \
  --trigger-http \
  --allow-unauthenticated \
  --timeout=540s \
  --memory=256MB \
  --set-env-vars MONGOSTRING='your-mongo-connection-string',PRKEY='your-private-key',ENVIRONMENT='production'
```

## ✅ Testing Deployment

Setelah deployment berhasil:

```bash
# Get function URL
FUNCTION_URL=$(gcloud functions describe go-gcp-function --region=asia-southeast2 --format="value(serviceConfig.uri)")

# Test endpoints
curl "$FUNCTION_URL/"
curl "$FUNCTION_URL/health"
curl "$FUNCTION_URL/api/users"
```

## 🔧 Environment Variables yang Digunakan

| Secret Name | Digunakan untuk | Sumber |
|-------------|-----------------|---------|
| `GOOGLE_CREDENTIALS` | Authentication ke GCP | Service Account JSON |
| `MONGOSTRING` | Koneksi ke MongoDB | MongoDB Atlas connection string |
| `PRKEY` | Private key aplikasi | Custom key untuk authentication |

## 📡 Function Details

- **Function Name:** `go-gcp-function`
- **Region:** `asia-southeast2`
- **Runtime:** `go122`
- **Memory:** 256MB
- **Timeout:** 540s
- **Trigger:** HTTP (public access)

## 🎉 Hasil Deployment

Setelah berhasil deploy, Anda akan mendapat:

1. **Function URL** - Untuk mengakses aplikasi
2. **Health Check** - `[FUNCTION_URL]/health`
3. **API Endpoints** - `[FUNCTION_URL]/api/*`

## 🚨 Troubleshooting

### Jika GitHub Actions gagal:

1. **Check Secrets:**
   - Repository Settings > Secrets and variables > Actions
   - Pastikan `GOOGLE_CREDENTIALS`, `MONGOSTRING`, `PRKEY` ada

2. **Check Service Account Permissions:**
   - Cloud Functions Developer
   - Artifact Registry Admin
   - Logging Viewer

3. **View Logs:**
   ```bash
   gcloud functions logs read go-gcp-function --region=asia-southeast2
   ```

### Jika Function Error:

```bash
# Check function status
gcloud functions describe go-gcp-function --region=asia-southeast2

# View real-time logs
gcloud functions logs tail go-gcp-function --region=asia-southeast2
```

---

**🎯 Kesimpulan:** Dengan GitHub Actions, deployment jadi otomatis setiap kali Anda push ke main branch. Secrets sudah ter-configure dengan benar untuk project `gwa-project-472118`.