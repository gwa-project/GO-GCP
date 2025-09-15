package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gocroot/config"
	"github.com/gocroot/helper"
	"github.com/gocroot/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// GetHome handles the home route
func GetHome(w http.ResponseWriter, r *http.Request) {
	response := helper.ResponseSuccess("Welcome gwa-project", map[string]interface{}{
		"version":     "1.0.0",
		"framework":   "gocroot",
		"environment": config.GetEnvironment(),
		"endpoints": []string{
			"GET /health - Health check",
			"GET /data/user - Get user data",
			"POST /data/user - Create user",
			"PUT /data/user - Update user",
			"DELETE /data/user - Delete user",
			"POST /auth/login - Login",
			"POST /auth/register - Register",
			"GET /api/users - Get all users",
		},
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetHealth handles health check
func GetHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := "disconnected"
	if config.Database != nil {
		dbStatus = "connected"
	}

	response := helper.ResponseSuccess("System healthy", map[string]interface{}{
		"database":    dbStatus,
		"environment": config.GetEnvironment(),
		"uptime":      time.Now(),
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetDataUser gets user data from token
func GetDataUser(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Login")
	if token == "" {
		response := helper.ResponseError("Login header required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify token
	userID, err := helper.VerifyPasetoToken(token)
	if err != nil {
		response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get user from database
	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var user model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("User data retrieved", user)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// PostDataUser creates a new user
func PostDataUser(w http.ResponseWriter, r *http.Request) {
	var createReq model.CreateUserRequest

	err := json.NewDecoder(r.Body).Decode(&createReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create new user
	user := model.User{
		Name:        createReq.Name,
		Email:       createReq.Email,
		PhoneNumber: createReq.PhoneNumber,
		Role:        "user",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	result, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		response := helper.ResponseError("Failed to create user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	response := helper.ResponseSuccess("User created successfully", user)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// PutDataUser updates user data
func PutDataUser(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Login")
	if token == "" {
		response := helper.ResponseError("Login header required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify token
	userID, err := helper.VerifyPasetoToken(token)
	if err != nil {
		response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	var updateReq model.UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	if updateReq.Name != "" {
		update["$set"].(bson.M)["name"] = updateReq.Name
	}
	if updateReq.Email != "" {
		update["$set"].(bson.M)["email"] = updateReq.Email
	}
	if updateReq.PhoneNumber != "" {
		update["$set"].(bson.M)["phonenumber"] = updateReq.PhoneNumber
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		response := helper.ResponseError("Failed to update user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("User updated successfully", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DeleteDataUser deletes user
func DeleteDataUser(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Login")
	if token == "" {
		response := helper.ResponseError("Login header required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify token
	userID, err := helper.VerifyPasetoToken(token)
	if err != nil {
		response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": objectID})
	if err != nil {
		response := helper.ResponseError("Failed to delete user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("User deleted successfully", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Login handles user login
func Login(w http.ResponseWriter, r *http.Request) {
	var loginReq model.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// For demo purposes, accept any non-empty credentials
	if loginReq.Email == "" || loginReq.Password == "" {
		response := helper.ResponseError("Email and password are required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Demo: create a fake user ID
	userID := helper.GenerateID()

	// Create PASETO token
	token, err := helper.CreatePasetoToken(userID, 24*time.Hour)
	if err != nil {
		response := helper.ResponseError("Failed to create token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Login successful", map[string]interface{}{
		"token":      token,
		"expires_at": time.Now().Add(24 * time.Hour),
		"user": map[string]interface{}{
			"id":    userID,
			"email": loginReq.Email,
			"name":  "Demo User",
		},
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Register handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	var registerReq model.RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&registerReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create new user
	user := model.User{
		Name:        registerReq.Name,
		Email:       registerReq.Email,
		PhoneNumber: registerReq.PhoneNumber,
		Password:    registerReq.Password, // In production, hash this
		Role:        "user",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	result, err := collection.InsertOne(context.Background(), user)
	if err != nil {
		response := helper.ResponseError("Failed to register user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	user.Password = "" // Don't return password

	// Create token
	token, err := helper.CreatePasetoToken(user.ID.Hex(), 24*time.Hour)
	if err != nil {
		response := helper.ResponseError("Failed to create token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Registration successful", map[string]interface{}{
		"token": token,
		"user":  user,
	})
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// GetAllUsers gets all users (for demo)
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	collection := config.GetCollection("users")
	if collection == nil {
		// Return demo data if no database
		demoUsers := []map[string]interface{}{
			{
				"id":    "demo-1",
				"name":  "Demo User 1",
				"email": "demo1@example.com",
			},
			{
				"id":    "demo-2",
				"name":  "Demo User 2",
				"email": "demo2@example.com",
			},
		}
		response := helper.ResponseSuccess("Demo users retrieved", demoUsers)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		response := helper.ResponseError("Failed to fetch users", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer cursor.Close(context.Background())

	var users []model.User
	err = cursor.All(context.Background(), &users)
	if err != nil {
		response := helper.ResponseError("Failed to decode users", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Users retrieved successfully", users)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// NotFound handles 404 errors
func NotFound(w http.ResponseWriter, r *http.Request) {
	response := helper.ResponseError("Endpoint not found", http.StatusNotFound)
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(response)
}