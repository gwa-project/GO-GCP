package config

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MongoClient *mongo.Client
var Database *mongo.Database

// ConnectMongoDB connects to MongoDB
func ConnectMongoDB() {
	mongoString := GetMongoString()
	if mongoString == "" {
		log.Println("Warning: MONGOSTRING not set, MongoDB will not be connected")
		return
	}

	log.Printf("Attempting to connect to MongoDB...")
	// Hide password in logs
	safeMongoString := mongoString
	if len(mongoString) > 20 {
		safeMongoString = mongoString[:10] + "***" + mongoString[len(mongoString)-10:]
	}
	log.Printf("MongoDB URI: %s", safeMongoString)

	clientOptions := options.Client().ApplyURI(mongoString)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Printf("Failed to connect to MongoDB: %v", err)
		return
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Printf("Failed to ping MongoDB: %v", err)
		return
	}

	MongoClient = client
	Database = client.Database("gogcp")
	log.Println("Connected to MongoDB successfully")
}

// GetDatabase returns the database instance
func GetDatabase() *mongo.Database {
	if Database == nil {
		ConnectMongoDB()
	}
	return Database
}

// GetCollection returns a collection from the database
func GetCollection(collectionName string) *mongo.Collection {
	db := GetDatabase()
	if db == nil {
		log.Printf("Database not connected, returning nil for collection: %s", collectionName)
		return nil
	}
	return db.Collection(collectionName)
}