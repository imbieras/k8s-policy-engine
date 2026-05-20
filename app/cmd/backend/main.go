// @title           Policy Engine API
// @version         1.0
// @description     JIT access management API for Kubernetes RBAC.
// @host            localhost:8080
// @BasePath        /
// @securityDefinitions.apikey  BearerAuth
// @in                          header
// @name                        Authorization
// @description                 Type "Bearer" followed by a space and your token.

package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"policy-engine/pkg/audit"
	authpkg "policy-engine/pkg/auth"
	"policy-engine/pkg/db"
	"policy-engine/pkg/detector"
	"policy-engine/pkg/models"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"

	_ "policy-engine/docs"
)

var (
	database         *gorm.DB
	kubernetesClient *db.KubernetesClient
	sessionStore     *authpkg.Store
	oidcVerifier     *authpkg.Verifier
	deviceProxy      *authpkg.DeviceProxy
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

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}
	sessionStore, err = authpkg.NewStore(redisAddr)
	if err != nil {
		log.Fatalf("redis session store: %v", err)
	}
	defer sessionStore.Close()

	if oidcIssuer := os.Getenv("OIDC_ISSUER"); oidcIssuer != "" {
		oidcClientID := os.Getenv("OIDC_CLIENT_ID")
		oidcTokenIssuer := os.Getenv("OIDC_TOKEN_ISSUER")
		for attempt := 1; attempt <= 30; attempt++ {
			oidcVerifier, err = authpkg.NewVerifier(context.Background(), oidcIssuer, oidcClientID, oidcTokenIssuer)
			if err == nil {
				break
			}
			if attempt == 30 {
				log.Fatalf("oidc verifier: %v", err)
			}
			log.Printf("OIDC not ready (attempt %d/30), retrying in 5s: %v", attempt, err)
			time.Sleep(5 * time.Second)
		}
		deviceProxy = authpkg.NewDeviceProxy(oidcIssuer, oidcClientID, os.Getenv("KEYCLOAK_EXTERNAL_URL"))
		log.Printf("OIDC enabled: issuer=%s client=%s", oidcIssuer, oidcClientID)
	}

	audit.InitGeoIP(os.Getenv("GEOIP_DB_PATH"))

	auditLogPath := os.Getenv("AUDIT_LOG_PATH")
	if auditLogPath == "" {
		auditLogPath = "audit.jsonl"
	}
	auditSink, err := audit.NewSink(auditLogPath)
	if err != nil {
		log.Fatalf("audit sink: %v", err)
	}
	defer auditSink.Close()

	auditCh := make(chan audit.AuditRecord, 512)

	ortLibPath := os.Getenv("ORT_LIB_LOCATION")
	xgbPath    := os.Getenv("POLICY_ENGINE_MODEL_PATH_XGB")
	lgbmPath   := os.Getenv("POLICY_ENGINE_MODEL_PATH_LGBM")

	if xgbPath != "" && lgbmPath != "" {
		if err := detector.InitORT(ortLibPath); err != nil {
			log.Printf("Warning: ORT init failed: %v - anomaly detection disabled", err)
			go func() { for range auditCh {} }()
		} else {
			defer detector.ShutdownORT()

			xgbScorer, err := detector.NewScorer(xgbPath)
			if err != nil {
				log.Fatalf("XGB scorer: %v", err)
			}
			defer xgbScorer.Close()

			lgbmScorer, err := detector.NewScorer(lgbmPath)
			if err != nil {
				log.Fatalf("LGBM scorer: %v", err)
			}
			defer lgbmScorer.Close()

			rb := detector.NewRingBuffer(200)

			const alertT  = float32(0.5)
			const revokeT = float32(0.85)

			xgbReactor  := detector.NewReactor("XGB",  alertT)
			lgbmReactor := detector.NewReactor("LGBM", alertT)

			revokeFn := func(sessionID string) error {
				var req models.Request
				if err := database.First(&req, "id = ?", sessionID).Error; err == nil {
					if err := sessionStore.Revoke(context.Background(), req.UserIdentity); err != nil {
						log.Printf("Warning: failed to revoke Redis session for %s: %v", req.UserIdentity, err)
					}
				}
				if err := database.Model(&models.Request{}).
					Where("id = ?", sessionID).
					Update("status", models.StatusRevoked).Error; err != nil {
					return err
				}
				if kubernetesClient != nil {
					ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer cancel()
					_ = kubernetesClient.DeleteRoleBinding(ctx, sessionID)
				}
				return nil
			}

			go func() {
				for rec := range auditCh {
					rb.Add(rec)
					fv := rb.Features(rec)

					xgbScore, xgbLat, xgbErr := xgbScorer.Score(fv)
					if xgbErr != nil {
						log.Printf("XGB score error event=%s: %v", rec.EventID, xgbErr)
						continue
					}

					lgbmScore, lgbmLat, lgbmErr := lgbmScorer.Score(fv)
					if lgbmErr != nil {
						log.Printf("LGBM score error event=%s: %v", rec.EventID, lgbmErr)
						continue
					}

					xgbReactor.Process(xgbScore, xgbLat, rec)
					lgbmReactor.Process(lgbmScore, lgbmLat, rec)

					if xgbScore >= revokeT && lgbmScore >= revokeT && rec.SessionID != "" {
						if err := revokeFn(rec.SessionID); err != nil {
							log.Printf("revoke error session=%s: %v", rec.SessionID, err)
						} else {
							log.Printf("REVOKED [XGB+LGBM] session=%s xgb=%.3f lgbm=%.3f",
								rec.SessionID, xgbScore, lgbmScore)
						}
					}
				}
			}()
			log.Printf("Dual anomaly detector loaded: XGB=%s LGBM=%s", xgbPath, lgbmPath)
		}
	} else {
		log.Printf("Warning: POLICY_ENGINE_MODEL_PATH_XGB or _LGBM not set - anomaly detection disabled")
		go func() { for range auditCh {} }()
	}

	router := gin.Default()
	router.Use(audit.Middleware(auditSink, auditCh))

	router.POST("/request", authMiddleware(), createRequest)
	router.GET("/requests", authMiddleware(), listRequests)
	router.POST("/approve/:id", authMiddleware(), approveRequest)

	if deviceProxy != nil {
		router.POST("/v1/auth/device", deviceProxy.HandleDevice)
		router.POST("/v1/auth/token", deviceProxy.HandleToken)
	}

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

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

func jwtSecret() string {
	if s := os.Getenv("JWT_SECRET"); s != "" {
		return s
	}
	return "dev-secret-change-in-prod"
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

		var sub string
		if oidcVerifier != nil {
			if oidcClaims, err := oidcVerifier.Verify(c.Request.Context(), raw); err == nil {
				sub = oidcClaims.Sub
			} else {
				log.Printf("OIDC verify failed: %v", err)
			}
		}
		if sub == "" {
			claims, err := authpkg.VerifyJWT(raw, jwtSecret())
			if err != nil {
				log.Printf("JWT verify failed: %v", err)
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				c.Abort()
				return
			}
			sub = claims.Sub
		}

		c.Set("sub", sub)
		c.Set("session_id", sessionStore.Lookup(c.Request.Context(), sub))
		c.Next()
	}
}

// createRequest godoc
// @Summary      Submit access request
// @Description  Creates a JIT access request for a Kubernetes role
// @Tags         requests
// @Accept       json
// @Produce      json
// @Param        request  body      RequestPayload   true  "Access request payload"
// @Success      202      {object}  models.Request
// @Failure      400      {object}  map[string]string
// @Failure      500      {object}  map[string]string
// @Security     BearerAuth
// @Router       /request [post]
func createRequest(c *gin.Context) {
	var payload RequestPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.Set("request_role", payload.Role)

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

// listRequests godoc
// @Summary      List all requests
// @Description  Get all access requests for the approver
// @Tags         requests
// @Produce      json
// @Success      200  {array}   models.Request
// @Failure      500  {object}  map[string]string
// @Security     BearerAuth
// @Router       /requests [get]
func listRequests(c *gin.Context) {
	var requests []models.Request
	if err := database.Find(&requests).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch requests"})
		return
	}

	c.JSON(http.StatusOK, requests)
}

// approveRequest godoc
// @Summary      Approve an access request
// @Description  Approves a request and create the RoleBinding in Kubernetes
// @Tags         requests
// @Produce      json
// @Param        id   path      string  true  "Request ID"
// @Success      200  {object}  ApprovalResponse
// @Failure      400  {object}  map[string]string
// @Failure      404  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Security     BearerAuth
// @Router       /approve/{id} [post]
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

	if err := sessionStore.Approve(context.Background(), request.UserIdentity, request.ID, duration); err != nil {
		log.Printf("Warning: failed to write session to Redis: %v", err)
	}

	if kubernetesClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := kubernetesClient.CreateRoleBinding(ctx, &request); err != nil {
			log.Printf("Warning: Failed to create RoleBinding: %v", err)
		}
	}

	c.JSON(http.StatusOK, ApprovalResponse{
		ID:        request.ID,
		Status:    request.Status,
		ExpiresAt: expiresAt,
	})
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
				_ = sessionStore.Revoke(context.Background(), req.UserIdentity)
				log.Printf("Revoked request %s for user %s", req.ID, req.UserIdentity)
			}
		}
	}
}
