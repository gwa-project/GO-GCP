package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gwa-project/GO-GCP/config"
	"github.com/gwa-project/GO-GCP/route"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Connect to MongoDB if connection string is provided
	if cfg.MongoString != "" {
		config.ConnectMongoDB()
		log.Println("MongoDB connection initialized")
	} else {
		log.Println("Warning: MONGOSTRING not set, running without database")
	}

	// Setup HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Enable CORS for development
		config.SetCORS(w, r)

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Route the request
		route.HandleRequest(w, r)
	})

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Local development server starting on port %s", port)
	log.Printf("📍 Server running at: http://localhost:%s", port)
	log.Printf("🔍 Health check: http://localhost:%s/health", port)
	log.Printf("📡 API endpoint: http://localhost:%s/api", port)

	// Start server
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}