package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
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
	var registerReq model.RegisterRequest

	err := json.NewDecoder(r.Body).Decode(&registerReq)
	if err != nil {
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
		response := helper.ResponseError(err.Error(), http.StatusBadRequest)
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
	user := model.User{
		Name:        registerReq.Name,
		Email:       registerReq.Email,
		PhoneNumber: registerReq.PhoneNumber,
		Password:    hashedPassword,
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
		"id":           configData.ID,
		"app_name":     configData.AppName,
		"app_version":  configData.AppVersion,
		"environment":  configData.Environment,
		"created_at":   configData.CreatedAt,
		"updated_at":   configData.UpdatedAt,
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

// NotFound handles 404 errors
func NotFound(w http.ResponseWriter, r *http.Request) {
	response := helper.ResponseError("Endpoint not found", http.StatusNotFound)
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(response)
}