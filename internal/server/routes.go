package server

import (
	"handyhub-auth-svc/internal/config"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var logger = logrus.StandardLogger()

func SetupRoutes(router *gin.Engine, cfg *config.Configuration) {
	router.Use(enableCORS)

	// Health endpoint
	router.GET("/health", func(c *gin.Context) {
		logrus.Info("Health check requested")
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "auth-service",
			"version": "1.0.0",
		})
	})

	// API version group
	api := router.Group("/api/v1")
	{
		api.GET("/status", func(c *gin.Context) {
			logrus.Info("API status requested")
			c.JSON(200, gin.H{
				"api_version": "v1",
				"status":      "operational",
				"service":     "handyhub-auth-svc",
			})
		})
	}

	// Auth endpoints group (пока заглушки)
	auth := router.Group("/auth")
	{
		auth.POST("/login", func(c *gin.Context) {
			logger.Info("Login endpoint called")
			c.JSON(200, gin.H{
				"message": "Login endpoint - coming soon",
			})
		})

		auth.POST("/register", func(c *gin.Context) {
			logger.Info("Register endpoint called")
			c.JSON(200, gin.H{
				"message": "Register endpoint - coming soon",
			})
		})

		auth.POST("/logout", func(c *gin.Context) {
			logger.Info("Logout endpoint called")
			c.JSON(200, gin.H{
				"message": "Logout endpoint - coming soon",
			})
		})

		auth.POST("/refresh", func(c *gin.Context) {
			logger.Info("Refresh endpoint called")
			c.JSON(200, gin.H{
				"message": "Refresh endpoint - coming soon",
			})
		})

		auth.POST("/reset-password", func(c *gin.Context) {
			logger.Info("Reset password endpoint called")
			c.JSON(200, gin.H{
				"message": "Reset password endpoint - coming soon",
			})
		})

		auth.GET("/verify-token", func(c *gin.Context) {
			logger.Info("Verify token endpoint called")
			c.JSON(200, gin.H{
				"message": "Verify token endpoint - coming soon",
			})
		})

		auth.POST("/change-password", func(c *gin.Context) {
			logger.Info("Change password endpoint called")
			c.JSON(200, gin.H{
				"message": "Change password endpoint - coming soon",
			})
		})
	}
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
