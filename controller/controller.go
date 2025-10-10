package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gocroot/config"
	"github.com/gocroot/helper"
	"github.com/gocroot/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// getStringFromInterface safely converts interface{} to string
func getStringFromInterface(value interface{}) string {
	if value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return ""
}

// GetHome handles the home route
func GetHome(w http.ResponseWriter, r *http.Request) {
	response := helper.ResponseSuccess("Welcome gwa-project", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetConfig handles configuration for frontend
func GetConfig(w http.ResponseWriter, r *http.Request) {
	// Ensure default config exists
	ensureDefaultConfig()

	configData := config.GetConfigForAPI()
	response := helper.ResponseSuccess("Configuration data", configData)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ensureDefaultConfig creates default config if not exists
func ensureDefaultConfig() {
	collection := config.GetCollection("config")
	if collection == nil {
		return
	}

	// Check if config exists
	var existingConfig model.Config
	err := collection.FindOne(context.Background(), bson.M{}).Decode(&existingConfig)

	if err != nil {
		// Config doesn't exist, create default
		defaultConfig := model.Config{
			AppName:            "GWA Project",
			AppVersion:         "1.0.0",
			Environment:        os.Getenv("ENVIRONMENT"),
			GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			MongoString:        os.Getenv("MONGOSTRING"),
			PrivateKey:         os.Getenv("PRKEY"),
			CreatedAt:          time.Now(),
			UpdatedAt:          time.Now(),
		}

		collection.InsertOne(context.Background(), defaultConfig)
	}
}

// GetDataUser gets user data from token
func GetDataUser(w http.ResponseWriter, r *http.Request) {
	// Get token from header (support both Login and Authorization)
	token := r.Header.Get("Login")
	if token == "" {
		// Try Authorization header for JWT Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" && len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			token = authHeader[7:]
		}
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
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

// Login handles user login (including Google OAuth)
func Login(w http.ResponseWriter, r *http.Request) {
	var loginReq model.LoginRequest

	err := json.NewDecoder(r.Body).Decode(&loginReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if this is Google OAuth login
	if loginReq.GoogleAuth {
		// Handle Google OAuth login with proper token verification
		handleGoogleAuth(w, r, loginReq)
		return
	}

	// Regular email/password login
	if loginReq.Email == "" || loginReq.Password == "" {
		response := helper.ResponseError("Email and password are required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate email format
	if !helper.ValidateEmail(loginReq.Email) {
		response := helper.ResponseError("Invalid email format", http.StatusBadRequest)
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

	// Find user by email
	var user model.User
	err = collection.FindOne(context.Background(), bson.M{"email": loginReq.Email}).Decode(&user)
	if err != nil {
		response := helper.ResponseError("Invalid email or password", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check password
	if !helper.CheckPassword(loginReq.Password, user.Password) {
		response := helper.ResponseError("Invalid email or password", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Update last login time
	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}
	collection.UpdateOne(context.Background(), bson.M{"_id": user.ID}, update)

	// Create tokens
	tokenDuration := 1 * time.Hour // Default 1 hour
	if loginReq.RememberMe {
		tokenDuration = 7 * 24 * time.Hour // 7 days if remember me
	}

	accessToken, err := helper.CreatePasetoToken(user.ID.Hex(), tokenDuration)
	if err != nil {
		response := helper.ResponseError("Failed to create access token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	refreshToken, err := helper.CreateRefreshToken(user.ID.Hex())
	if err != nil {
		response := helper.ResponseError("Failed to create refresh token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prepare response
	tokens := model.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenDuration.Seconds()),
		ExpiresAt:    time.Now().Add(tokenDuration),
	}

	// Remove sensitive data from user object
	user.Password = ""

	authResponse := model.AuthResponse{
		User:    user,
		Tokens:  tokens,
		Message: "Login successful",
	}

	response := helper.ResponseSuccess("Login successful", authResponse)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleGoogleAuth handles Google OAuth authentication with proper token verification
func handleGoogleAuth(w http.ResponseWriter, r *http.Request, loginReq model.LoginRequest) {
	// Verify Google token first
	if loginReq.GoogleToken == "" {
		response := helper.ResponseError("Google token is required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify the Google token
	tokenInfo, err := helper.VerifyGoogleToken(loginReq.GoogleToken)
	if err != nil {
		helper.LogError("Google token verification failed", err)
		response := helper.ResponseError("Invalid Google token", http.StatusUnauthorized)
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

	// Check if user already exists
	var existingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"email": tokenInfo.Email}).Decode(&existingUser)

	var user model.User
	isNewUser := false

	if err != nil {
		// User doesn't exist, create new user
		isNewUser = true
		user = model.User{
			Name:      tokenInfo.Name,
			Email:     tokenInfo.Email,
			Picture:   tokenInfo.Picture,
			GoogleID:  tokenInfo.Sub,
			Role:      "user",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		result, err := collection.InsertOne(context.Background(), user)
		if err != nil {
			response := helper.ResponseError("Failed to create user", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		user.ID = result.InsertedID.(primitive.ObjectID)
		helper.LogInfo(fmt.Sprintf("New user created via Google OAuth: %s", user.Email))
	} else {
		// User exists, update Google data and last login
		update := bson.M{
			"$set": bson.M{
				"updated_at": time.Now(),
				"picture":    tokenInfo.Picture,
				"google_id":  tokenInfo.Sub,
				"name":       tokenInfo.Name, // Update name from Google
			},
		}

		_, err = collection.UpdateOne(context.Background(), bson.M{"_id": existingUser.ID}, update)
		if err != nil {
			response := helper.ResponseError("Failed to update user", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}

		user = existingUser
		user.Picture = tokenInfo.Picture
		user.GoogleID = tokenInfo.Sub
		user.Name = tokenInfo.Name
		user.UpdatedAt = time.Now()
		helper.LogInfo(fmt.Sprintf("User logged in via Google OAuth: %s", user.Email))
	}

	// Create tokens
	tokenDuration := 1 * time.Hour // Default 1 hour
	if loginReq.RememberMe {
		tokenDuration = 7 * 24 * time.Hour // 7 days if remember me
	}

	accessToken, err := helper.CreatePasetoToken(user.ID.Hex(), tokenDuration)
	if err != nil {
		response := helper.ResponseError("Failed to create access token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	refreshToken, err := helper.CreateRefreshToken(user.ID.Hex())
	if err != nil {
		response := helper.ResponseError("Failed to create refresh token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prepare response
	tokens := model.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenDuration.Seconds()),
		ExpiresAt:    time.Now().Add(tokenDuration),
	}

	googleAuthResponse := model.GoogleAuthResponse{
		User:        user,
		Tokens:      tokens,
		IsNewUser:   isNewUser,
		LastLoginAt: time.Now(),
	}

	response := helper.ResponseSuccess("Google login successful", googleAuthResponse)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Register handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("Register endpoint called")
	var registerReq model.RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&registerReq)
	if err != nil {
		helper.LogError("Invalid JSON in register request", err)
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate required fields
	if registerReq.Name == "" || registerReq.Email == "" || registerReq.Password == "" {
		response := helper.ResponseError("Name, email, and password are required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate email format
	if !helper.ValidateEmail(registerReq.Email) {
		response := helper.ResponseError("Invalid email format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate password strength
	if err := helper.ValidatePassword(registerReq.Password); err != nil {
		helper.LogError("Password validation failed", err)
		response := helper.ResponseError(err.Error(), http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("users")
	if collection == nil {
		helper.LogError("Database not connected in Register endpoint", nil)
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if user already exists
	var existingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"email": registerReq.Email}).Decode(&existingUser)
	if err == nil {
		response := helper.ResponseError("User with this email already exists", http.StatusConflict)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Hash password
	hashedPassword, err := helper.HashPassword(registerReq.Password)
	if err != nil {
		response := helper.ResponseError("Failed to secure password", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create new user
	// Check if this is the first user (make them admin)
	count, err := collection.CountDocuments(context.Background(), bson.M{})
	if err != nil {
		helper.LogError("Error counting users", err)
		response := helper.ResponseError("Database error", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Set role - first user becomes admin, others become user
	role := "user"
	if count == 0 {
		role = "admin"
		helper.LogInfo("Creating first user as admin: " + registerReq.Email)
	}

	user := model.User{
		Name:        registerReq.Name,
		Email:       registerReq.Email,
		PhoneNumber: registerReq.PhoneNumber,
		DiscordID:   registerReq.DiscordID,
		Password:    hashedPassword,
		Role:        role,
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

	// Create tokens
	tokenDuration := 1 * time.Hour
	accessToken, err := helper.CreatePasetoToken(user.ID.Hex(), tokenDuration)
	if err != nil {
		response := helper.ResponseError("Failed to create access token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	refreshToken, err := helper.CreateRefreshToken(user.ID.Hex())
	if err != nil {
		response := helper.ResponseError("Failed to create refresh token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prepare response
	tokens := model.TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenDuration.Seconds()),
		ExpiresAt:    time.Now().Add(tokenDuration),
	}

	authResponse := model.AuthResponse{
		User:    user,
		Tokens:  tokens,
		Message: "Registration successful",
	}

	helper.LogInfo(fmt.Sprintf("New user registered: %s", user.Email))
	response := helper.ResponseSuccess("Registration successful", authResponse)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}


// PostConfig handles creating/updating config (admin only)
func PostConfig(w http.ResponseWriter, r *http.Request) {
	var configReq model.CreateConfigRequest

	err := json.NewDecoder(r.Body).Decode(&configReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("config")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if config already exists
	var existingConfig model.Config
	err = collection.FindOne(context.Background(), bson.M{}).Decode(&existingConfig)

	configData := model.Config{
		AppName:            configReq.AppName,
		AppVersion:         configReq.AppVersion,
		Environment:        configReq.Environment,
		GoogleClientID:     configReq.GoogleClientID,
		GoogleClientSecret: configReq.GoogleClientSecret,
		MongoString:        configReq.MongoString,
		PrivateKey:         configReq.PrivateKey,
		UpdatedAt:          time.Now(),
	}

	if err != nil {
		// Config doesn't exist, create new
		configData.CreatedAt = time.Now()
		result, err := collection.InsertOne(context.Background(), configData)
		if err != nil {
			response := helper.ResponseError("Failed to create config", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}
		configData.ID = result.InsertedID.(primitive.ObjectID)
	} else {
		// Config exists, update it
		configData.ID = existingConfig.ID
		configData.CreatedAt = existingConfig.CreatedAt
		_, err = collection.ReplaceOne(context.Background(), bson.M{"_id": existingConfig.ID}, configData)
		if err != nil {
			response := helper.ResponseError("Failed to update config", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}
	}

	response := helper.ResponseSuccess("Config saved successfully", map[string]interface{}{
		"id":          configData.ID,
		"app_name":    configData.AppName,
		"app_version": configData.AppVersion,
		"environment": configData.Environment,
		"created_at":  configData.CreatedAt,
		"updated_at":  configData.UpdatedAt,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// RefreshToken handles token refresh
func RefreshToken(w http.ResponseWriter, r *http.Request) {
	var refreshReq model.RefreshTokenRequest

	err := json.NewDecoder(r.Body).Decode(&refreshReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	if refreshReq.RefreshToken == "" {
		response := helper.ResponseError("Refresh token is required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify refresh token
	userID, err := helper.VerifyPasetoToken(refreshReq.RefreshToken)
	if err != nil {
		response := helper.ResponseError("Invalid or expired refresh token", http.StatusUnauthorized)
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

	// Create new tokens
	tokenDuration := 1 * time.Hour
	newAccessToken, err := helper.CreatePasetoToken(userID, tokenDuration)
	if err != nil {
		response := helper.ResponseError("Failed to create new access token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	newRefreshToken, err := helper.CreateRefreshToken(userID)
	if err != nil {
		response := helper.ResponseError("Failed to create new refresh token", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prepare response
	tokens := model.TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tokenDuration.Seconds()),
		ExpiresAt:    time.Now().Add(tokenDuration),
	}

	response := helper.ResponseSuccess("Tokens refreshed successfully", tokens)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetProfile handles getting current user profile
func GetProfile(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
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

	// Remove sensitive information
	user.Password = ""

	response := helper.ResponseSuccess("User profile retrieved successfully", user)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdateProfile handles updating current user profile
func UpdateProfile(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}
	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
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

	// Parse request body
	var updateReq model.UpdateUserRequest
	err = json.NewDecoder(r.Body).Decode(&updateReq)
	if err != nil {
		response := helper.ResponseError("Invalid JSON format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get database collection
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

	// Prepare update document
	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	// Only update fields that are provided
	if updateReq.Name != "" {
		update["$set"].(bson.M)["name"] = updateReq.Name
	}
	if updateReq.PhoneNumber != "" {
		update["$set"].(bson.M)["phonenumber"] = updateReq.PhoneNumber
	}

	// Update user profile
	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		response := helper.ResponseError("Failed to update profile", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Profile updated successfully", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// Logout handles user logout (invalidate tokens)
func Logout(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token != "" {
		// Verify token
		userID, err := helper.VerifyPasetoToken(token)
		if err == nil {
			// Log the logout
			helper.LogInfo(fmt.Sprintf("User logged out: %s", userID))
		}
	}

	// Since PASETO tokens are stateless, we can't invalidate them server-side
	// In a production environment, you might want to maintain a blacklist
	// or use shorter token expiration times

	response := helper.ResponseSuccess("Logged out successfully", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ChangePassword handles password change requests
func ChangePassword(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("ChangePassword endpoint called")
	var changeReq model.ChangePasswordRequest

	err := json.NewDecoder(r.Body).Decode(&changeReq)
	if err != nil {
		response := helper.ResponseError("Invalid request body", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get token from header
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify token and get user ID
	userID, err := helper.VerifyPasetoToken(token)
	if err != nil {
		response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get database collection
	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Convert userID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Find user
	var user model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&user)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify current password
	if !helper.CheckPassword(changeReq.CurrentPassword, user.Password) {
		response := helper.ResponseError("Current password is incorrect", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate new password
	if len(changeReq.NewPassword) < 6 {
		response := helper.ResponseError("New password must be at least 6 characters long", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Hash new password
	hashedPassword, err := helper.HashPassword(changeReq.NewPassword)
	if err != nil {
		response := helper.ResponseError("Failed to hash password", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Update password in database
	update := bson.M{
		"$set": bson.M{
			"password":   hashedPassword,
			"updated_at": time.Now(),
		},
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": objectID}, update)
	if err != nil {
		response := helper.ResponseError("Failed to update password", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Password changed successfully", nil)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetAllUsers handles admin request to get all users
func GetAllUsers(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("GetAllUsers endpoint called")

	// Get token from header
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Verify token and get user ID
	userID, err := helper.VerifyPasetoToken(token)
	if err != nil {
		response := helper.ResponseError("Invalid or expired token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get database collection
	collection := config.GetCollection("users")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if requesting user is admin
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&requestingUser)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestingUser.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get all users
	cursor, err := collection.Find(context.Background(), bson.M{})
	if err != nil {
		response := helper.ResponseError("Failed to retrieve users", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}
	defer cursor.Close(context.Background())

	var users []model.User
	for cursor.Next(context.Background()) {
		var user model.User
		if err := cursor.Decode(&user); err != nil {
			continue
		}
		// Remove password from response
		user.Password = ""
		users = append(users, user)
	}

	response := helper.ResponseSuccess("Users retrieved successfully", users)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// CreateUser handles admin request to create new user
func CreateUser(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("CreateUser endpoint called")
	var userReq model.AdminUserRequest

	err := json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		response := helper.ResponseError("Invalid request body", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get token and verify admin access
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

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

	// Check if requesting user is admin
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&requestingUser)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestingUser.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate required fields
	if userReq.Name == "" || userReq.Email == "" || userReq.Password == "" {
		response := helper.ResponseError("Name, email, and password are required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if email already exists
	var existingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"email": userReq.Email}).Decode(&existingUser)
	if err == nil {
		response := helper.ResponseError("Email already exists", http.StatusConflict)
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate role
	if userReq.Role != "admin" && userReq.Role != "user" {
		userReq.Role = "user" // Default to user
	}

	// Hash password
	hashedPassword, err := helper.HashPassword(userReq.Password)
	if err != nil {
		response := helper.ResponseError("Failed to hash password", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create new user
	newUser := model.User{
		ID:          primitive.NewObjectID(),
		Name:        userReq.Name,
		Email:       userReq.Email,
		PhoneNumber: userReq.PhoneNumber,
		Password:    hashedPassword,
		Role:        userReq.Role,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err = collection.InsertOne(context.Background(), newUser)
	if err != nil {
		response := helper.ResponseError("Failed to create user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Remove password from response
	newUser.Password = ""

	response := helper.ResponseSuccess("User created successfully", newUser)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// GetUserByID handles admin request to get user by ID
func GetUserByID(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("GetUserByID endpoint called")

	// Extract user ID from URL path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		response := helper.ResponseError("User ID required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	targetUserID := parts[len(parts)-1]

	// Get token and verify admin access
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

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

	// Check if requesting user is admin
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&requestingUser)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestingUser.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get target user
	targetObjectID, err := primitive.ObjectIDFromHex(targetUserID)
	if err != nil {
		response := helper.ResponseError("Invalid target user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var targetUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": targetObjectID}).Decode(&targetUser)
	if err != nil {
		response := helper.ResponseError("Target user not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Remove password from response
	targetUser.Password = ""

	response := helper.ResponseSuccess("User retrieved successfully", targetUser)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdateUser handles admin request to update user
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("UpdateUser endpoint called")

	// Extract user ID from URL path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		response := helper.ResponseError("User ID required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	targetUserID := parts[len(parts)-1]

	var userReq model.AdminUserRequest
	err := json.NewDecoder(r.Body).Decode(&userReq)
	if err != nil {
		response := helper.ResponseError("Invalid request body", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get token and verify admin access
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

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

	// Check if requesting user is admin
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&requestingUser)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestingUser.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate target user ID
	targetObjectID, err := primitive.ObjectIDFromHex(targetUserID)
	if err != nil {
		response := helper.ResponseError("Invalid target user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if target user exists
	var targetUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": targetObjectID}).Decode(&targetUser)
	if err != nil {
		response := helper.ResponseError("Target user not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prepare update data
	updateData := bson.M{
		"updated_at": time.Now(),
	}

	if userReq.Name != "" {
		updateData["name"] = userReq.Name
	}

	if userReq.Email != "" {
		// Check if email already exists (excluding current user)
		var existingUser model.User
		err = collection.FindOne(context.Background(), bson.M{
			"email": userReq.Email,
			"_id":   bson.M{"$ne": targetObjectID},
		}).Decode(&existingUser)
		if err == nil {
			response := helper.ResponseError("Email already exists", http.StatusConflict)
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(response)
			return
		}
		updateData["email"] = userReq.Email
	}

	if userReq.PhoneNumber != "" {
		updateData["phonenumber"] = userReq.PhoneNumber
	}

	if userReq.Role != "" {
		if userReq.Role == "admin" || userReq.Role == "user" {
			updateData["role"] = userReq.Role
		}
	}

	// Handle password update if provided
	if userReq.Password != "" {
		hashedPassword, err := helper.HashPassword(userReq.Password)
		if err != nil {
			response := helper.ResponseError("Failed to hash password", http.StatusInternalServerError)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(response)
			return
		}
		updateData["password"] = hashedPassword
	}

	// Update user
	update := bson.M{"$set": updateData}
	_, err = collection.UpdateOne(context.Background(), bson.M{"_id": targetObjectID}, update)
	if err != nil {
		response := helper.ResponseError("Failed to update user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get updated user
	err = collection.FindOne(context.Background(), bson.M{"_id": targetObjectID}).Decode(&targetUser)
	if err != nil {
		response := helper.ResponseError("Failed to retrieve updated user", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Remove password from response
	targetUser.Password = ""

	response := helper.ResponseSuccess("User updated successfully", targetUser)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// DeleteUser handles admin request to delete user
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	helper.LogInfo("DeleteUser endpoint called")

	// Extract user ID from URL path
	path := r.URL.Path
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		response := helper.ResponseError("User ID required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}
	targetUserID := parts[len(parts)-1]

	// Get token and verify admin access
	token := r.Header.Get("Authorization")
	if token != "" && len(token) > 7 && token[:7] == "Bearer " {
		token = token[7:]
	}

	if token == "" {
		token = r.Header.Get("Login")
	}

	if token == "" {
		response := helper.ResponseError("Authorization token required", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

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

	// Check if requesting user is admin
	objectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		response := helper.ResponseError("Invalid user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	var requestingUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": objectID}).Decode(&requestingUser)
	if err != nil {
		response := helper.ResponseError("User not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	if requestingUser.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Validate target user ID
	targetObjectID, err := primitive.ObjectIDFromHex(targetUserID)
	if err != nil {
		response := helper.ResponseError("Invalid target user ID", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Prevent admin from deleting themselves
	if userID == targetUserID {
		response := helper.ResponseError("Cannot delete your own account", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if target user exists
	var targetUser model.User
	err = collection.FindOne(context.Background(), bson.M{"_id": targetObjectID}).Decode(&targetUser)
	if err != nil {
		response := helper.ResponseError("Target user not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Delete user
	_, err = collection.DeleteOne(context.Background(), bson.M{"_id": targetObjectID})
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

// NotFound handles 404 errors
func NotFound(w http.ResponseWriter, r *http.Request) {
	response := helper.ResponseError("Endpoint not found", http.StatusNotFound)
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(response)
}
