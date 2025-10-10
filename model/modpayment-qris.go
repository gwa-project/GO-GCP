package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// PaymentMethod represents the type of payment method used
type PaymentMethod string

const (
	QRIS PaymentMethod = "qris"
)

// CrowdfundingOrder struct to store QRIS payment data
type CrowdfundingOrder struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	OrderID       string             `json:"orderId" bson:"orderId"`
	Name          string             `json:"name" bson:"name"`
	PhoneNumber   string             `json:"phoneNumber" bson:"phoneNumber"`
	NPM           string             `json:"npm,omitempty" bson:"npm,omitempty"`
	Amount        float64            `json:"amount" bson:"amount"`
	PaymentMethod PaymentMethod      `json:"paymentMethod" bson:"paymentMethod"`
	Timestamp     time.Time          `json:"timestamp" bson:"timestamp"`
	ExpiryTime    time.Time          `json:"expiryTime" bson:"expiryTime"`
	Status        string             `json:"status" bson:"status"` // pending, success, failed
	UpdatedAt     time.Time          `json:"updatedAt,omitempty" bson:"updatedAt,omitempty"`
}

// CrowdfundingQueue struct to manage payment processing
type CrowdfundingQueue struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	IsProcessing   bool               `json:"isProcessing" bson:"isProcessing"`
	CurrentOrderID string             `json:"currentOrderId" bson:"currentOrderId"`
	PaymentMethod  PaymentMethod      `json:"paymentMethod" bson:"paymentMethod"`
	ExpiryTime     time.Time          `json:"expiryTime" bson:"expiryTime"`
}

// CrowdfundingTotal struct to track total QRIS payments
type CrowdfundingTotal struct {
	ID              primitive.ObjectID `bson:"_id,omitempty" json:"_id,omitempty"`
	TotalQRISAmount float64            `json:"totalQRISAmount" bson:"totalQRISAmount"`
	QRISCount       int                `json:"qrisCount" bson:"qrisCount"`
	LastUpdated     time.Time          `json:"lastUpdated" bson:"lastUpdated"`
}

// CreateQRISOrderRequest represents the request body for creating a QRIS order
type CreateQRISOrderRequest struct {
	Amount float64 `json:"amount"`
}

// NotificationRequest for receiving notification text from payment gateway
type NotificationRequest struct {
	NotificationText string `json:"notification_text"`
}

// CrowdfundingPaymentResponse represents QRIS payment response
type CrowdfundingPaymentResponse struct {
	Success       bool          `json:"success"`
	Message       string        `json:"message,omitempty"`
	OrderID       string        `json:"orderId,omitempty"`
	ExpiryTime    time.Time     `json:"expiryTime,omitempty"`
	QRISImageURL  string        `json:"qrisImageUrl,omitempty"`
	QRImageURL    string        `json:"qrImageUrl,omitempty"` // For backward compatibility
	QueueStatus   bool          `json:"queueStatus,omitempty"`
	Status        string        `json:"status,omitempty"`
	IsProcessing  bool          `json:"isProcessing,omitempty"`
	PaymentMethod PaymentMethod `json:"paymentMethod,omitempty"`
}
