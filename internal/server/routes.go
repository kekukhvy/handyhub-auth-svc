package server

import (
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/dependency"
	"handyhub-auth-svc/internal/middleware"

	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func SetupRoutes(deps *dependency.Manager) {
	router := deps.Router
	router.Use(enableCORS)
	router.Use(middleware.RequestLoggingMiddleware())

	setupHealthEndpoint(deps)
	setupPublicRoutes(router, deps)
	setupProtectedRoutes(router, deps)
}

func setupHealthEndpoint(deps *dependency.Manager) {
	router := deps.Router
	mongodb := deps.Mongodb
	redisClient := deps.Redis
	cfg := deps.Config

	router.GET("/health", func(c *gin.Context) {
		log.Info("Health check endopint requested")

		mongoStatus := "ok"
		if err := mongodb.Client.Ping(c.Request.Context(), nil); err != nil {
			mongoStatus = "error: " + err.Error()
		}

		redisStatus := "ok"
		if err := redisClient.Ping(c.Request.Context()).Err(); err != nil {
			redisStatus = "error: " + err.Error()
		}

		c.JSON(200, gin.H{
			"status":    "ok",
			"service":   cfg.App.Name,
			"version":   cfg.App.Version,
			"mongodb":   mongoStatus,
			"redis":     redisStatus,
			"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05Z07:00"),
		})
	})

	router.GET("health/detailed", func(c *gin.Context) {
		log.Info("Detailed health check endpoint requested")

		c.JSON(200, gin.H{
			"status":  "operational",
			"service": cfg.App.Name,
			"version": cfg.App.Version,
			"components": gin.H{
				"database": gin.H{
					"mongodb": getStatus(isMonoConnected(mongodb, c)),
					"redis":   getStatus(isRedisConnected(redisClient, c)),
				},
				"services": gin.H{
					"auth":    "operational",
					"session": "operational",
					"cache":   "operational",
				},
			},
		})
	})
}

func setupPublicRoutes(router *gin.Engine, deps *dependency.Manager) {
	// API status endpoint
	router.GET("/api/v1/status", func(c *gin.Context) {
		log.Info("API status requested")
		c.JSON(200, gin.H{
			"api_version": "v1",
			"status":      "operational",
			"service":     "handyhub-auth-svc",
		})
	})

	// Authentication endpoints (public)
	auth := router.Group("/auth")
	{
		auth.POST("/register", deps.AuthHandler.Register)
		auth.POST("/login", deps.AuthHandler.Login)
		auth.POST("/reset-password", deps.AuthHandler.ResetPassword)
		auth.POST("/reset-password-confirm", deps.AuthHandler.ResetPasswordConfirm)
		auth.GET("/verify-email", deps.AuthHandler.VerifyEmail)
		auth.GET("/verify-token", deps.AuthHandler.VerifyToken)
		auth.POST("/refresh", deps.AuthHandler.RefreshToken)
	}
}

func setupProtectedRoutes(router *gin.Engine, deps *dependency.Manager) {
	protected := router.Group("/auth")
	protected.Use(deps.AuthMiddleware.RequireAuth())
	{
		protected.POST("/change-password", deps.AuthHandler.ChangePassword)
	}
}

func isMonoConnected(mongodb *clients.MongoDB, c *gin.Context) bool {
	if err := mongodb.Client.Ping(c.Request.Context(), nil); err != nil {
		return false
	}
	return true
}

func isRedisConnected(redisClient *redis.Client, c *gin.Context) bool {
	if err := redisClient.Ping(c.Request.Context()).Err(); err != nil {
		return false
	}
	return true
}

func enableCORS(c *gin.Context) {
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if c.Request.Method == "OPTIONS" {
		c.AbortWithStatus(204)
		return
	}

	c.Next()
}

func getStatus(b bool) string {
	if b {
		return "connected"
	}
	return "disconnected"
}
