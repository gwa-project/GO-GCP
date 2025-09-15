package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
	"github.com/gwa-project/GO-GCP/config"
	"github.com/gwa-project/GO-GCP/route"
)

func init() {
	// Register Cloud Function entry point
	functions.HTTP("WebHook", WebHook)
}

// WebHook is the Cloud Function entry point
func WebHook(w http.ResponseWriter, r *http.Request) {
	// Enable CORS
	config.SetCORS(w, r)

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Route the request
	route.HandleRequest(w, r)
}

// For local development
func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}