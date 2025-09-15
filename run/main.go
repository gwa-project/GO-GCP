package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gocroot/config"
	"github.com/gocroot/route"
)

func main() {
	// Load configuration and connect to MongoDB
	config.SetEnv()
	config.ConnectMongoDB()

	// Setup HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		route.URL(w, r)
	})

	// Get port from environment variable or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🚀 Local development server starting on port %s", port)
	log.Printf("📍 Server running at: http://localhost:%s", port)
	log.Printf("🔍 Health check: http://localhost:%s/health", port)
	log.Printf("📡 API endpoints:")
	log.Printf("   GET  / - Home page")
	log.Printf("   GET  /health - Health check")
	log.Printf("   GET  /data/user - Get user data (requires Login header)")
	log.Printf("   POST /data/user - Create user")
	log.Printf("   PUT  /data/user - Update user (requires Login header)")
	log.Printf("   DELETE /data/user - Delete user (requires Login header)")
	log.Printf("   POST /auth/login - Login")
	log.Printf("   POST /auth/register - Register")
	log.Printf("   GET  /api/users - Get all users")

	// Start server
	if err := http.ListenAndServe(fmt.Sprintf(":%s", port), nil); err != nil {
		log.Fatal("Server failed to start:", err)
	}
}