package controller

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gwa-project/GO-GCP/helper"
	"github.com/gwa-project/GO-GCP/model"
)

// LoginRequest represents a login request
type LoginRequest struct {
	UserID   string `json:"user_id"`
	Password string `json:"password"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token     string                `json:"token"`
	ExpiresAt time.Time            `json:"expires_at"`
	User      model.User           `json:"user"`
}

// Login handles user login and returns PASETO token
func Login(w http.ResponseWriter, r *http.Request) {
	var loginReq LoginRequest

	// Decode request body
	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate credentials (simplified - implement your own validation)
	if loginReq.UserID == "" || loginReq.Password == "" {
		response := helper.ResponseError("User ID and password are required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// TODO: Implement actual user authentication with database
	// For now, accept any non-empty credentials
	if loginReq.Password != "demo123" { // Demo password
		response := helper.ResponseError("Invalid credentials", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create PASETO token
	pasetoMaker, err := helper.NewPasetoMaker()
	if err != nil {
		helper.LogError("Failed to create PASETO maker", err)
		response := helper.ResponseError("Internal server error", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Generate token with 24 hours expiration
	duration := 24 * time.Hour
	token, err := pasetoMaker.CreateToken(loginReq.UserID, duration)
	if err != nil {
		helper.LogError("Failed to create token", err)
		response := helper.ResponseError("Internal server error", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create user object (in real app, get from database)
	user := model.User{
		ID:        loginReq.UserID,
		Name:      "Demo User",
		Email:     loginReq.UserID + "@example.com",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Prepare response
	loginResponse := LoginResponse{
		Token:     token,
		ExpiresAt: time.Now().Add(duration),
		User:      user,
	}

	response := helper.ResponseSuccess("Login successful", loginResponse)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// VerifyToken middleware to verify PASETO token
func VerifyToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			response := helper.ResponseError("Authorization header is required", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		// Extract token from "Bearer <token>"
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			response := helper.ResponseError("Invalid authorization header format", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		token := tokenParts[1]

		// Verify token
		pasetoMaker, err := helper.NewPasetoMaker()
		if err != nil {
			helper.LogError("Failed to create PASETO maker", err)
			response := helper.ResponseError("Internal server error", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		payload, err := pasetoMaker.VerifyToken(token)
		if err != nil {
			response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(response)
			return
		}

		// Add user ID to request context for use in next handler
		r.Header.Set("X-User-ID", payload.UserID)
		next(w, r)
	}
}

// GetProfile returns user profile (protected endpoint)
func GetProfile(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")

	// TODO: Get user from database
	user := model.User{
		ID:    userID,
		Name:  "Demo User",
		Email: userID + "@example.com",
	}

	response := helper.ResponseSuccess("Profile retrieved successfully", user)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}