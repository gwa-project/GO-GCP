package route

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gwa-project/GO-GCP/controller"
)

// HandleRequest routes HTTP requests
func HandleRequest(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	segments := strings.Split(path, "/")

	// Set content type
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case "GET":
		handleGETRoutes(w, r, segments)
	case "POST":
		handlePOSTRoutes(w, r, segments)
	case "PUT":
		handlePUTRoutes(w, r, segments)
	case "DELETE":
		handleDELETERoutes(w, r, segments)
	default:
		sendErrorResponse(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGETRoutes handles GET requests
func handleGETRoutes(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 || segments[0] == "" {
		controller.GetHome(w, r)
		return
	}

	switch segments[0] {
	case "health":
		controller.GetHealth(w, r)
	case "api":
		if len(segments) > 1 {
			switch segments[1] {
			case "users":
				controller.GetUsers(w, r)
			case "login":
				controller.Login(w, r)
			case "profile":
				// Protected endpoint - requires authentication
				controller.VerifyToken(controller.GetProfile)(w, r)
			default:
				sendErrorResponse(w, "API endpoint not found", http.StatusNotFound)
			}
		} else {
			sendErrorResponse(w, "API endpoint not specified", http.StatusBadRequest)
		}
	default:
		sendErrorResponse(w, "Route not found", http.StatusNotFound)
	}
}

// handlePOSTRoutes handles POST requests
func handlePOSTRoutes(w http.ResponseWriter, r *http.Request, segments []string) {
	if len(segments) == 0 || segments[0] == "" {
		sendErrorResponse(w, "Invalid POST route", http.StatusBadRequest)
		return
	}

	switch segments[0] {
	case "api":
		if len(segments) > 1 {
			switch segments[1] {
			case "users":
				controller.CreateUser(w, r)
			case "login":
				controller.Login(w, r)
			default:
				sendErrorResponse(w, "API endpoint not found", http.StatusNotFound)
			}
		} else {
			sendErrorResponse(w, "API endpoint not specified", http.StatusBadRequest)
		}
	default:
		sendErrorResponse(w, "Route not found", http.StatusNotFound)
	}
}

// handlePUTRoutes handles PUT requests
func handlePUTRoutes(w http.ResponseWriter, r *http.Request, segments []string) {
	sendErrorResponse(w, "PUT method not implemented", http.StatusNotImplemented)
}

// handleDELETERoutes handles DELETE requests
func handleDELETERoutes(w http.ResponseWriter, r *http.Request, segments []string) {
	sendErrorResponse(w, "DELETE method not implemented", http.StatusNotImplemented)
}

// sendErrorResponse sends an error response
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int) {
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error":   true,
		"message": message,
		"code":    statusCode,
	}
	json.NewEncoder(w).Encode(response)
}