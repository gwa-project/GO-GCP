package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gocroot/config"
	"github.com/gocroot/helper"
	"github.com/gocroot/model"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	QRISExpirySeconds = 3600 // 60 minutes
)

// InitializeWebhookSecret initializes webhook secret if it doesn't exist
func InitializeWebhookSecret() {
	collection := config.GetCollection("webhooksecret")
	if collection == nil {
		return
	}

	var existingSecret model.WebhookSecret
	err := collection.FindOne(context.Background(), bson.M{"isActive": true}).Decode(&existingSecret)
	if err != nil {
		// No active secret exists, create one
		secretKey := fmt.Sprintf("GWA-WEBHOOK-%s-%s",
			uuid.New().String()[:8],
			uuid.New().String()[:8])

		_, err = collection.InsertOne(context.Background(), model.WebhookSecret{
			SecretKey:   secretKey,
			Description: "Auto-generated webhook secret for QRIS payment notifications",
			IsActive:    true,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		})
		if err != nil {
			log.Printf("Error initializing webhook secret: %v", err)
		} else {
			log.Printf("Initialized webhook secret: %s", secretKey)
		}
	} else {
		log.Printf("Webhook secret already exists: %s", existingSecret.SecretKey)
	}
}

// InitializeCrowdfundingTotal initializes the total payments collection if it doesn't exist
func InitializeCrowdfundingTotal() {
	var total model.CrowdfundingTotal
	collection := config.GetCollection("crowdfundingtotals")
	if collection == nil {
		return
	}

	err := collection.FindOne(context.Background(), bson.M{}).Decode(&total)
	if err != nil {
		// Total document doesn't exist, create it
		_, err = collection.InsertOne(context.Background(), model.CrowdfundingTotal{
			TotalQRISAmount: 0,
			QRISCount:       0,
			LastUpdated:     time.Now(),
		})
		if err != nil {
			log.Printf("Error initializing crowdfunding totals: %v", err)
		} else {
			log.Println("Initialized crowdfunding totals successfully")
		}
	}
}

// InitializeCrowdfundingQueue initializes the queue
func InitializeCrowdfundingQueue() {
	var queue model.CrowdfundingQueue
	collection := config.GetCollection("crowdfundingqueue")
	if collection == nil {
		return
	}

	err := collection.FindOne(context.Background(), bson.M{}).Decode(&queue)
	if err != nil {
		// Queue document doesn't exist, create it
		_, err = collection.InsertOne(context.Background(), model.CrowdfundingQueue{
			IsProcessing:   false,
			CurrentOrderID: "",
			ExpiryTime:     time.Time{},
		})
		if err != nil {
			log.Printf("Error initializing crowdfunding queue: %v", err)
		} else {
			log.Println("Initialized crowdfunding queue successfully")
		}
	}
}

// Helper function to update payment totals
func updateCrowdfundingTotal(amount float64) {
	collection := config.GetCollection("crowdfundingtotals")
	if collection == nil {
		return
	}

	opts := options.FindOneAndUpdate().SetUpsert(true)
	update := bson.M{
		"$inc": bson.M{
			"totalQRISAmount": amount,
			"qrisCount":       1,
		},
		"$set": bson.M{
			"lastUpdated": time.Now(),
		},
	}

	var result model.CrowdfundingTotal
	err := collection.FindOneAndUpdate(
		context.Background(),
		bson.M{},
		update,
		opts,
	).Decode(&result)

	if err != nil {
		log.Printf("Error updating crowdfunding totals: %v", err)
	}
}

// CleanupExpiredQueue automatically cleans up any expired payment queue entries
func CleanupExpiredQueue() {
	collection := config.GetCollection("crowdfundingqueue")
	if collection == nil {
		return
	}

	var queue model.CrowdfundingQueue
	err := collection.FindOne(context.Background(), bson.M{}).Decode(&queue)
	if err != nil {
		return
	}

	// Check if there's an active payment that has expired
	if queue.IsProcessing && !queue.ExpiryTime.IsZero() && time.Now().After(queue.ExpiryTime) {
		log.Printf("Found expired payment in queue, order ID: %s", queue.CurrentOrderID)

		// Reset the queue
		_, err = collection.UpdateOne(
			context.Background(),
			bson.M{},
			bson.M{"$set": bson.M{
				"isProcessing":   false,
				"currentOrderId": "",
				"paymentMethod":  "",
				"expiryTime":     time.Time{},
			}},
		)

		if err != nil {
			log.Printf("Error resetting expired queue: %v", err)
		} else {
			log.Println("Successfully reset expired payment queue")

			// Update order status
			if queue.CurrentOrderID != "" {
				ordersCollection := config.GetCollection("crowdfundingorders")
				if ordersCollection != nil {
					_, err = ordersCollection.UpdateOne(
						context.Background(),
						bson.M{"orderId": queue.CurrentOrderID},
						bson.M{"$set": bson.M{
							"status":    "failed",
							"updatedAt": time.Now(),
						}},
					)
					if err != nil {
						log.Printf("Error updating expired order status: %v", err)
					}
				}
			}
		}
	}
}

// CheckQueueStatus checks if there's an active payment in the queue
func CheckQueueStatus(w http.ResponseWriter, r *http.Request) {
	CleanupExpiredQueue()

	collection := config.GetCollection("crowdfundingqueue")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var queue model.CrowdfundingQueue
	err := collection.FindOne(context.Background(), bson.M{}).Decode(&queue)
	if err != nil {
		InitializeCrowdfundingQueue()
		InitializeCrowdfundingTotal()

		response := helper.ResponseSuccess("Queue status", model.CrowdfundingPaymentResponse{
			Success:      true,
			IsProcessing: false,
		})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check for expired payments
	if queue.IsProcessing && !queue.ExpiryTime.IsZero() && time.Now().After(queue.ExpiryTime) {
		log.Printf("Detected expired payment: %s", queue.CurrentOrderID)

		_, updateErr := collection.UpdateOne(
			context.Background(),
			bson.M{},
			bson.M{"$set": bson.M{
				"isProcessing":   false,
				"currentOrderId": "",
				"paymentMethod":  "",
				"expiryTime":     time.Time{},
			}},
		)

		if updateErr != nil {
			log.Printf("Error resetting expired queue: %v", updateErr)
		}

		response := helper.ResponseSuccess("Queue status", model.CrowdfundingPaymentResponse{
			Success:      true,
			IsProcessing: false,
			Message:      "Previous payment session expired",
		})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Queue status", model.CrowdfundingPaymentResponse{
		Success:       true,
		IsProcessing:  queue.IsProcessing,
		ExpiryTime:    queue.ExpiryTime,
		PaymentMethod: queue.PaymentMethod,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetUserInfoQRIS returns the user information from token
func GetUserInfoQRIS(w http.ResponseWriter, r *http.Request) {
	// Get token from header
	token := r.Header.Get("Login")
	if token == "" {
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

	// Return user info for crowdfunding
	userInfo := map[string]interface{}{
		"name":        user.Name,
		"phoneNumber": user.PhoneNumber,
		"npm":         "", // NPM field tidak ada di model.User, set empty string
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// CreateQRISOrder creates a new QRIS payment order
func CreateQRISOrder(w http.ResponseWriter, r *http.Request) {
	var request model.CreateQRISOrderRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		response := helper.ResponseError("Invalid request body", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Get token
	token := r.Header.Get("Login")
	if token == "" {
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

	// Get user info
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

	// Validate request
	if request.Amount <= 0 {
		response := helper.ResponseError("Valid amount is required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check queue
	queueCollection := config.GetCollection("crowdfundingqueue")
	if queueCollection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var queue model.CrowdfundingQueue
	err = queueCollection.FindOne(context.Background(), bson.M{}).Decode(&queue)
	if err != nil {
		InitializeCrowdfundingQueue()
	} else if queue.IsProcessing {
		response := helper.ResponseSuccess("Queue status", model.CrowdfundingPaymentResponse{
			Success:       false,
			Message:       "Sedang ada pembayaran berlangsung. Silakan tunggu.",
			QueueStatus:   true,
			ExpiryTime:    queue.ExpiryTime,
			PaymentMethod: queue.PaymentMethod,
		})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Create order
	orderID := uuid.New().String()
	expiryTime := time.Now().Add(QRISExpirySeconds * time.Second)

	newOrder := model.CrowdfundingOrder{
		OrderID:       orderID,
		Name:          user.Name,
		PhoneNumber:   user.PhoneNumber,
		NPM:           "", // NPM tidak ada di model.User
		Amount:        request.Amount,
		PaymentMethod: model.QRIS,
		Timestamp:     time.Now(),
		ExpiryTime:    expiryTime,
		Status:        "pending",
	}

	ordersCollection := config.GetCollection("crowdfundingorders")
	if ordersCollection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	_, err = ordersCollection.InsertOne(context.Background(), newOrder)
	if err != nil {
		response := helper.ResponseError("Error creating order", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Update queue
	_, err = queueCollection.UpdateOne(
		context.Background(),
		bson.M{},
		bson.M{"$set": bson.M{
			"isProcessing":   true,
			"currentOrderId": orderID,
			"paymentMethod":  model.QRIS,
			"expiryTime":     expiryTime,
		}},
		options.Update().SetUpsert(true),
	)

	if err != nil {
		response := helper.ResponseError("Error updating queue", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	log.Printf("QRIS order created: %s for %s, Amount: Rp %.2f", orderID, user.Name, request.Amount)

	// Set expiry timer
	go func() {
		time.Sleep(QRISExpirySeconds * time.Second)

		var currentQueue model.CrowdfundingQueue
		err := queueCollection.FindOne(context.Background(), bson.M{}).Decode(&currentQueue)
		if err != nil {
			return
		}

		if currentQueue.CurrentOrderID == orderID {
			// Update order status
			ordersCollection.UpdateOne(
				context.Background(),
				bson.M{"orderId": orderID},
				bson.M{"$set": bson.M{
					"status":    "failed",
					"updatedAt": time.Now(),
				}},
			)

			// Reset queue
			queueCollection.UpdateOne(
				context.Background(),
				bson.M{},
				bson.M{"$set": bson.M{
					"isProcessing":   false,
					"currentOrderId": "",
					"paymentMethod":  "",
					"expiryTime":     time.Time{},
				}},
			)

			log.Printf("Order expired: %s", orderID)
		}
	}()

	response := helper.ResponseSuccess("Order created", model.CrowdfundingPaymentResponse{
		Success:       true,
		OrderID:       orderID,
		ExpiryTime:    expiryTime,
		QRISImageURL:  "https://raw.githubusercontent.com/do-community/crowdfunding-FE/main/qris.png",
		PaymentMethod: model.QRIS,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// CheckPaymentStatus checks the status of a payment order
func CheckPaymentStatus(w http.ResponseWriter, r *http.Request) {
	// Extract orderID from URL path
	path := r.URL.Path
	orderID := path[len("/api/crowdfunding/checkPayment/"):]

	if orderID == "" {
		response := helper.ResponseError("Order ID required", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("crowdfundingorders")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var order model.CrowdfundingOrder
	err := collection.FindOne(context.Background(), bson.M{"orderId": orderID}).Decode(&order)
	if err != nil {
		response := helper.ResponseError("Order not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := helper.ResponseSuccess("Payment status", model.CrowdfundingPaymentResponse{
		Success: true,
		Status:  order.Status,
		OrderID: order.OrderID,
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetWebhookSecret returns the active webhook secret (admin only)
func GetWebhookSecret(w http.ResponseWriter, r *http.Request) {
	// Get user from context (set by authentication middleware)
	tokenString := r.Header.Get("Login")
	if tokenString == "" {
		response := helper.ResponseError("Unauthorized", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Decode token to get user role
	payload, err := helper.Decode(tokenString)
	if err != nil {
		response := helper.ResponseError("Invalid token", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if user is admin
	if payload.Role != "admin" {
		response := helper.ResponseError("Admin access required", http.StatusForbidden)
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(response)
		return
	}

	collection := config.GetCollection("webhooksecret")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var secret model.WebhookSecret
	err = collection.FindOne(context.Background(), bson.M{"isActive": true}).Decode(&secret)
	if err != nil {
		response := helper.ResponseError("Webhook secret not found", http.StatusNotFound)
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(response)
		return
	}

	response := map[string]interface{}{
		"success":     true,
		"secretKey":   secret.SecretKey,
		"description": secret.Description,
		"createdAt":   secret.CreatedAt,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ProcessNotification processes payment notification from gateway
func ProcessNotification(w http.ResponseWriter, r *http.Request) {
	// Validate webhook secret from header
	webhookSecret := r.Header.Get("X-Webhook-Secret")
	if webhookSecret == "" {
		response := helper.ResponseError("Missing webhook secret", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if secret is valid
	secretCollection := config.GetCollection("webhooksecret")
	if secretCollection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var storedSecret model.WebhookSecret
	err := secretCollection.FindOne(context.Background(), bson.M{
		"secretKey": webhookSecret,
		"isActive":  true,
	}).Decode(&storedSecret)

	if err != nil {
		response := helper.ResponseError("Invalid webhook secret", http.StatusUnauthorized)
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		log.Printf("Webhook authentication failed: invalid secret")
		return
	}

	var notification model.NotificationRequest
	if err := json.NewDecoder(r.Body).Decode(&notification); err != nil {
		response := helper.ResponseError("Invalid request body", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Parse notification text to extract order ID and amount
	orderID, amount, err := parseNotificationText(notification.NotificationText)
	if err != nil {
		response := helper.ResponseError("Invalid notification format", http.StatusBadRequest)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Update order status
	collection := config.GetCollection("crowdfundingorders")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"orderId": orderID},
		bson.M{"$set": bson.M{
			"status":    "success",
			"updatedAt": time.Now(),
		}},
	)

	if err != nil {
		response := helper.ResponseError("Error updating order", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Update totals
	updateCrowdfundingTotal(amount)

	// Reset queue
	queueCollection := config.GetCollection("crowdfundingqueue")
	if queueCollection != nil {
		queueCollection.UpdateOne(
			context.Background(),
			bson.M{},
			bson.M{"$set": bson.M{
				"isProcessing":   false,
				"currentOrderId": "",
				"paymentMethod":  "",
				"expiryTime":     time.Time{},
			}},
		)
	}

	log.Printf("Payment successful: %s, Amount: Rp %.2f", orderID, amount)

	response := helper.ResponseSuccess("Payment processed", map[string]interface{}{
		"success": true,
		"message": "Payment processed successfully",
	})
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetTotals returns total payments
func GetTotals(w http.ResponseWriter, r *http.Request) {
	collection := config.GetCollection("crowdfundingtotals")
	if collection == nil {
		response := helper.ResponseError("Database not connected", http.StatusInternalServerError)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)
		return
	}

	var total model.CrowdfundingTotal
	err := collection.FindOne(context.Background(), bson.M{}).Decode(&total)
	if err != nil {
		// Return empty totals
		total = model.CrowdfundingTotal{
			TotalQRISAmount: 0,
			QRISCount:       0,
			LastUpdated:     time.Now(),
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(total)
}

// Helper function to parse notification text
func parseNotificationText(text string) (orderID string, amount float64, err error) {
	// Example format: "Payment received for order ORDER_ID with amount 50000.00"
	// This is a simplified parser - adjust based on actual notification format

	// For now, just log the notification
	log.Printf("Received notification: %s", text)

	// Return dummy values - implement actual parsing logic based on your notification format
	return "", 0, fmt.Errorf("notification parsing not implemented")
}
