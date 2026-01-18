package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	_ "policy-engine/docs"
	"policy-engine/pkg/db"
	"policy-engine/pkg/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerfiles "github.com/swaggo/files"
	ginswagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

var (
	database         *gorm.DB
	kubernetesClient *db.KubernetesClient
)

type RequestPayload struct {
	User     string `json:"user" binding:"required"`
	Role     string `json:"role" binding:"required"`
	Reason   string `json:"reason"`
	Duration string `json:"duration" binding:"required"`
}

type ApprovalResponse struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenResponse struct {
	Token string `json:"token"`
}

// @title Policy Engine API
// @version 1.0
// @description Just-In-Time Access Control for Kubernetes
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the token value

func main() {
	var err error
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "requests.db"
	}

	database, err = db.InitDB(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	kubernetesClient, err = db.NewKubernetesClient("default")
	if err != nil {
		log.Printf("Warning: Failed to initialize Kubernetes client: %v", err)
		log.Println("Running in local mode without Kubernetes integration")
		kubernetesClient = nil
	}

	router := gin.Default()

	router.GET("/swagger/*any", ginswagger.WrapHandler(swaggerfiles.Handler))

	router.POST("/token", generateToken)

	router.POST("/request", authMiddleware(), createRequest)
	router.GET("/requests", authMiddleware(), listRequests)
	router.POST("/approve/:id", authMiddleware(), approveRequest)

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	go revokeExpiredRequests()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting Policy Engine on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "missing bearer token"})
			c.Abort()
			return
		}

		token := strings.TrimSpace(strings.TrimPrefix(auth, prefix))
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		var t models.Token
		if err := database.First(&t, "value = ?", token).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// generateToken handles POST /token
// @Summary Generate authentication token
// @Description Generate a new bearer token for API authentication. Use this token in the Authorization header as 'Bearer <token>'
// @Produce json
// @Success 200 {object} TokenResponse
// @Router /token [post]
func generateToken(c *gin.Context) {
	token := uuid.New().String()
	rec := &models.Token{Value: token, CreatedAt: time.Now()}
	if err := database.Create(rec).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store token"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{Token: token})
}

// createRequest handles POST /request
// @Summary Create an access request
// @Description Submit a new JIT access request
// @Accept json
// @Produce json
// @Param request body RequestPayload true "Access request"
// @Success 202 {object} models.Request
// @Security BearerAuth
// @Router /request [post]
func createRequest(c *gin.Context) {
	var payload RequestPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	request := &models.Request{
		ID:           uuid.New().String(),
		UserIdentity: payload.User,
		Role:         payload.Role,
		Reason:       payload.Reason,
		Duration:     payload.Duration,
		Status:       models.StatusPending,
		CreatedAt:    time.Now(),
	}

	if err := database.Create(request).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	c.JSON(http.StatusAccepted, request)
}

// listRequests handles GET /requests
// @Summary List all requests
// @Description Get all access requests for the approver
// @Produce json
// @Success 200 {array} models.Request
// @Security BearerAuth
// @Router /requests [get]
func listRequests(c *gin.Context) {
	var requests []models.Request
	if err := database.Find(&requests).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// approveRequest handles POST /approve/:id
// @Summary Approve an access request
// @Description Approve a request and create the RoleBinding in Kubernetes
// @Param id path string true "Request ID"
// @Success 200 {object} ApprovalResponse
// @Security BearerAuth
// @Router /approve/{id} [post]
func approveRequest(c *gin.Context) {
	requestID := c.Param("id")

	var request models.Request
	if err := database.First(&request, "id = ?", requestID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		return
	}

	if request.Status != models.StatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Request is not pending"})
		return
	}

	duration, err := time.ParseDuration(request.Duration)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid duration format"})
		return
	}

	expiresAt := time.Now().Add(duration)
	request.Status = models.StatusApproved
	request.ExpiresAt = &expiresAt

	if err := database.Save(&request).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update request"})
		return
	}

	if kubernetesClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := kubernetesClient.CreateRoleBinding(ctx, &request); err != nil {
			log.Printf("Warning: Failed to create RoleBinding: %v", err)
		}
	}

	response := ApprovalResponse{
		ID:        request.ID,
		Status:    request.Status,
		ExpiresAt: expiresAt,
	}

	c.JSON(http.StatusOK, response)
}

func revokeExpiredRequests() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		var expiredRequests []models.Request
		now := time.Now()

		if err := database.Where("status = ? AND expires_at < ?", models.StatusApproved, now).Find(&expiredRequests).Error; err != nil {
			log.Printf("Error querying expired requests: %v", err)
			continue
		}

		for _, req := range expiredRequests {
			if kubernetesClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				if err := kubernetesClient.DeleteRoleBinding(ctx, req.ID); err != nil {
					log.Printf("Warning: Failed to delete RoleBinding %s: %v", req.ID, err)
				}
				cancel()
			}

			if err := database.Model(&req).Update("status", models.StatusRevoked).Error; err != nil {
				log.Printf("Error updating request status: %v", err)
			} else {
				log.Printf("Revoked request %s for user %s", req.ID, req.UserIdentity)
			}
		}
	}
}
