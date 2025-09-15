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
		log.Fatal("MONGOSTRING environment variable is not set")
	}

	clientOptions := options.Client().ApplyURI(mongoString)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal("Failed to ping MongoDB:", err)
	}

	MongoClient = client
	Database = client.Database("gogcp") // Change database name as needed
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
	return GetDatabase().Collection(collectionName)
}