package dependency

import (
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/auth"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/email"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/user"
	"handyhub-auth-svc/internal/validators"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Manager struct {
	Router         *gin.Engine
	Config         *config.Configuration
	Mongodb        *clients.MongoDB
	Redis          *redis.Client
	RabbitMQ       *clients.RabbitMQ
	EmailService   email.Service
	UserRepository user.Repository
	UserService    user.Service
	AuthService    auth.Service
	AuthHandler    *auth.Handler
}

func NewDependencyManager(router *gin.Engine,
	cfg *config.Configuration,
	mongodb *clients.MongoDB,
	redisClient *redis.Client,
	rabbitMQ *clients.RabbitMQ) *Manager {
	requestValidator := validators.NewRequestValidator(cfg)
	emailService := email.NewEmailService(cfg, rabbitMQ)
	sessionManager := session.NewManager(mongodb, cfg)
	userRepository := user.NewUserRepository(mongodb, cfg.Database.UserCollection)
	cacheService := cache.NewCacheService(redisClient)
	userService := user.NewUserService(userRepository, emailService, &cfg.Cache, cacheService)
	authService := auth.NewAuthService(requestValidator, userService, cacheService, cfg, sessionManager)
	authHandler := auth.NewAuthHandler(cfg, authService)
	return &Manager{
		Router:         router,
		Config:         cfg,
		Mongodb:        mongodb,
		Redis:          redisClient,
		RabbitMQ:       rabbitMQ,
		EmailService:   emailService,
		UserRepository: userRepository,
		UserService:    userService,
		AuthService:    authService,
		AuthHandler:    authHandler,
	}
}
