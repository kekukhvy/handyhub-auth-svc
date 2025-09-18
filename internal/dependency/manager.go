package dependency

import (
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/auth"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/email"
	"handyhub-auth-svc/internal/middleware"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/user"
	"handyhub-auth-svc/internal/utils"
	"handyhub-auth-svc/internal/validators"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Manager struct {
	Router           *gin.Engine
	Config           *config.Configuration
	Mongodb          *clients.MongoDB
	Redis            *redis.Client
	RabbitMQ         *clients.RabbitMQ
	EmailService     email.Service
	UserRepository   user.Repository
	UserService      user.Service
	AuthService      auth.Service
	AuthHandler      auth.Handler
	TokenValidator   *validators.TokenValidator
	CacheService     cache.Service
	SessionManager   session.Manager
	AuthMiddleware   *middleware.AuthMiddleware
	ActivityConsumer session.Consumer
	SessionHandler   session.Handler
}

func NewDependencyManager(router *gin.Engine,
	mongodb *clients.MongoDB,
	redisClient *redis.Client,
	rabbitMQ *clients.RabbitMQ,
	cfg *config.Configuration) *Manager {
	tokenValidator := validators.NewTokenValidator()
	jwtManager := utils.NewJWTManager(cfg.Security.JwtKey, cfg.Security.AccessTokenExpiration, cfg.Security.RefreshTokenExpiration)
	requestValidator := validators.NewRequestValidator(cfg)
	emailService := email.NewEmailService(cfg, rabbitMQ)
	cacheService := cache.NewCacheService(redisClient, cfg)
	sessionManager := session.NewManager(mongodb, cfg, cacheService)
	sessionHandler := session.NewSessionHandler(cfg, sessionManager, requestValidator)
	userRepository := user.NewUserRepository(mongodb, cfg.Database.UserCollection)
	userService := user.NewUserService(userRepository, emailService, &cfg.Cache, cacheService)
	authService := auth.NewAuthService(requestValidator, userService, cfg, sessionManager, cacheService, jwtManager)
	authHandler := auth.NewAuthHandler(cfg, authService, tokenValidator)
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, sessionManager, userService)
	activityConsumer := session.NewConsumer(rabbitMQ.Channel, sessionManager, cacheService, cfg)
	return &Manager{
		Router:           router,
		Config:           cfg,
		Mongodb:          mongodb,
		Redis:            redisClient,
		RabbitMQ:         rabbitMQ,
		EmailService:     emailService,
		UserRepository:   userRepository,
		UserService:      userService,
		AuthService:      authService,
		AuthHandler:      authHandler,
		CacheService:     cacheService,
		SessionManager:   sessionManager,
		AuthMiddleware:   authMiddleware,
		ActivityConsumer: activityConsumer,
		SessionHandler:   sessionHandler,
	}
}
