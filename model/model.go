package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Name        string             `json:"name" bson:"name"`
	Email       string             `json:"email" bson:"email"`
	PhoneNumber string             `json:"phonenumber,omitempty" bson:"phonenumber,omitempty"`
	Password    string             `json:"-" bson:"password,omitempty"`
	Picture     string             `json:"picture,omitempty" bson:"picture,omitempty"`
	GoogleID    string             `json:"google_id,omitempty" bson:"google_id,omitempty"`
	Token       string             `json:"token,omitempty" bson:"token,omitempty"`
	Role        string             `json:"role,omitempty" bson:"role,omitempty"`
	CreatedAt   time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time          `json:"updated_at" bson:"updated_at"`
}

// Response represents a standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Code    int         `json:"code,omitempty"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	GoogleAuth  bool   `json:"google_auth,omitempty"`
	GoogleToken string `json:"google_token,omitempty"`
	RememberMe  bool   `json:"remember_me,omitempty"`
}

// RegisterRequest represents a registration request
type RegisterRequest struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	PhoneNumber string `json:"phonenumber,omitempty"`
	Password    string `json:"password"`
}

// CreateUserRequest represents the request to create a user
type CreateUserRequest struct {
	Name        string `json:"name" validate:"required"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phonenumber,omitempty"`
}

// UpdateUserRequest represents the request to update a user
type UpdateUserRequest struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phonenumber,omitempty"`
}

// Config represents application configuration stored in database
type Config struct {
	ID                 primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	AppName            string             `json:"app_name" bson:"app_name"`
	AppVersion         string             `json:"app_version" bson:"app_version"`
	Environment        string             `json:"environment" bson:"environment"`
	GoogleClientID     string             `json:"google_client_id" bson:"google_client_id"`
	GoogleClientSecret string             `json:"google_client_secret,omitempty" bson:"google_client_secret,omitempty"` // Don't expose in JSON
	MongoString        string             `json:"-" bson:"mongo_string,omitempty"` // Never expose
	PrivateKey         string             `json:"-" bson:"private_key,omitempty"`  // Never expose
	CreatedAt          time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at" bson:"updated_at"`
}

// CreateConfigRequest represents the request to create/update config
type CreateConfigRequest struct {
	AppName            string `json:"app_name"`
	AppVersion         string `json:"app_version"`
	Environment        string `json:"environment"`
	GoogleClientID     string `json:"google_client_id"`
	GoogleClientSecret string `json:"google_client_secret,omitempty"`
	MongoString        string `json:"mongo_string,omitempty"`
	PrivateKey         string `json:"private_key,omitempty"`
}

// TokenResponse represents authentication token response
type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshTokenRequest represents refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// GoogleAuthResponse represents Google OAuth response data
type GoogleAuthResponse struct {
	User         User          `json:"user"`
	Tokens       TokenResponse `json:"tokens"`
	IsNewUser    bool          `json:"is_new_user"`
	LastLoginAt  time.Time     `json:"last_login_at"`
}

// AuthResponse represents general authentication response
type AuthResponse struct {
	User    User          `json:"user"`
	Tokens  TokenResponse `json:"tokens"`
	Message string        `json:"message"`
}