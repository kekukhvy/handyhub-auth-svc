package auth

import (
	"context"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/user"

	"handyhub-auth-svc/internal/utils"
	"handyhub-auth-svc/internal/validators"

	"github.com/sirupsen/logrus"
)

type Service interface {
	// Authentication operations
	Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error)
}

var log = logrus.StandardLogger()

type authService struct {
	validator    *validators.RequestValidator
	userService  user.Service
	cacheService cache.Service
	cfg          *config.Configuration
}

func NewAuthService(validator *validators.RequestValidator, userService user.Service,
	cacheService cache.Service, cfg *config.Configuration) Service {
	return &authService{
		validator:    validator,
		userService:  userService,
		cacheService: cacheService,
		cfg:          cfg,
	}
}

// Register creates a new user account
func (s *authService) Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error) {
	// Validate request
	if validationErrors := s.validator.ValidateRegisterRequest(req); validationErrors.HasErrors() {
		log.WithField("errors", validationErrors.Errors).Error("Registration validation failed")
		return nil, models.ErrInvalidRequest
	}

	// Sanitize request
	s.validator.SanitizeRegisterRequest(req)

	// Check if email is unique
	isUnique, err := s.userService.IsEmailUnique(ctx, req.Email, nil)
	if err != nil {
		return nil, err
	}
	if !isUnique {
		return nil, models.ErrEmailAlreadyExists
	}

	// Convert request to user model
	user := req.ToUser()

	// Hash password
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		log.WithError(err).Error("Failed to hash password")
		return nil, models.ErrInternalServer
	}
	user.Password = hashedPassword

	// Create user
	createdUser, err := s.userService.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	// Cache user profile
	s.cacheService.CacheUserProfile(ctx, createdUser.ToProfile(), s.cfg.Cache.ExpirationMinutes)

	go s.userService.SendVerificationEmail(ctx, createdUser.ID)

	log.WithField("user_id", createdUser.ID.Hex()).
		WithField("email", createdUser.Email).
		Info("User registered successfully")

	return createdUser, nil
}
