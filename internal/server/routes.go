package server

import (
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/database"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Dependencies struct {
	Config      *config.Configuration
	MongoDB     *database.MongoDB
	RedisClient *redis.Client
	Router      *gin.Engine
}

func SetupRoutes(router *gin.Engine, cfg *config.Configuration,
	mongodb *database.MongoDB, redisClient *redis.Client) {

	router.Use(enableCORS)

	deps := initializeDependencies(cfg, mongodb, redisClient, router)
	setupHealthEndpoint(deps)
}

func initializeDependencies(cfg *config.Configuration, mongodb *database.MongoDB,
	redisClient *redis.Client, router *gin.Engine) *Dependencies {

	return &Dependencies{
		Config:      cfg,
		MongoDB:     mongodb,
		RedisClient: redisClient,
		Router:      router,
	}
}

func setupHealthEndpoint(deps *Dependencies) {
	router := deps.Router
	mongodb := deps.MongoDB
	redisClient := deps.RedisClient
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

func isMonoConnected(mongodb *database.MongoDB, c *gin.Context) bool {
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
