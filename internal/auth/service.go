package auth

import (
	"context"
	"errors"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/user"

	"handyhub-auth-svc/internal/utils"
	"handyhub-auth-svc/internal/validators"

	"github.com/sirupsen/logrus"
)

type Service interface {
	// Authentication operations
	Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error)
}

var log = logrus.StandardLogger()

type authService struct {
	validator      *validators.RequestValidator
	userService    user.Service
	cacheService   cache.Service
	sessionManager *session.Manager
	cfg            *config.Configuration
	jwtManager     *utils.JWTManager
}

func NewAuthService(validator *validators.RequestValidator, userService user.Service,
	cacheService cache.Service, cfg *config.Configuration, sessionManager *session.Manager) Service {
	return &authService{
		validator:      validator,
		userService:    userService,
		cacheService:   cacheService,
		cfg:            cfg,
		sessionManager: sessionManager,
		jwtManager:     utils.NewJWTManager(cfg.Security.JwtKey, cfg.Security.AccessTokenExpiration, cfg.Security.RefreshTokenExpiration),
	}
}

// Register creates a new user account
func (s *authService) Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error) {
	// Validate request
	log.WithField("email", req.Email).Info("Registering new user")
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
	s.cacheService.CacheUser(ctx, user, s.cfg.Cache.ExpirationMinutes)

	s.userService.SendVerificationEmail(ctx, createdUser.ID)

	return createdUser, nil
}

func (s *authService) Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error) {
	// Validate request
	if validationErrors := s.validator.ValidateLoginRequest(req); validationErrors.HasErrors() {
		log.WithField("errors", validationErrors.Errors).Error("Login validation failed")
		return nil, models.ErrInvalidCredentials
	}

	// Sanitize request
	s.validator.SanitizeLoginRequest(req)

	// Check rate limiting
	rateLimitKey := "login_attempts:" + req.Email
	if limited, err := s.cacheService.CheckRateLimit(ctx, rateLimitKey, s.cfg.Security.LoginRateLimit); err == nil && limited {
		log.WithField("email", req.Email).Warn("Login rate limit exceeded")
		return nil, models.ErrLoginAttemptsExceeded
	}

	// Get user by email
	user, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			// Still increment rate limit to prevent email enumeration
			s.cacheService.IncrementRateLimit(ctx, rateLimitKey, 900)
			return nil, models.ErrInvalidCredentials
		}
		return nil, err
	}

	if !user.IsActive() {
		log.WithField("user_id", user.ID.Hex()).Warn("Inactive user login attempt")
		return nil, models.ErrUserInactive
	}

	// Verify password
	if !utils.ComparePasswords(user.Password, req.Password) {
		// Increment failed login attempts
		s.userService.IncrementFailedLogin(ctx, user.ID)
		s.cacheService.IncrementRateLimit(ctx, rateLimitKey, 900)

		log.WithField("email", user.Email).Warn("Invalid password attempt")
		return nil, models.ErrInvalidCredentials
	}

	// Reset failed login attempts on successful login
	s.cacheService.ResetFailedLoginAttempts(ctx, rateLimitKey)

	// Create session (IP and UserAgent would be passed from handler)
	session, err := s.sessionManager.CreateSession(ctx, user.ID, "", "")
	if err != nil {
		log.WithError(err).WithField("user_id", user.ID.Hex()).Error("Failed to create session")
		return nil, models.ErrSessionCreating
	}

	// Generate tokens
	accessToken, accessExpiresAt, err := s.jwtManager.GenerateAccessToken(user.ID, session.SessionID, user.Email, user.Role)
	if err != nil {
		log.WithError(err).Error("Failed to generate access token")
		return nil, models.ErrTokenGenerating
	}

	refreshToken, refreshExpiresAt, err := s.jwtManager.GenerateRefreshToken(user.ID, session.SessionID)
	if err != nil {
		log.WithError(err).Error("Failed to generate refresh token")
		return nil, models.ErrTokenGenerating
	}

	// Update session with refresh token
	session.RefreshToken = refreshToken
	session.AccessToken = accessToken
	session.ExpiresAt = accessExpiresAt

	s.sessionManager.Update(ctx, session)

	// Cache active session
	s.cacheService.CacheActiveSession(ctx, session)

	// Update user last login
	s.userService.UpdateLastLogin(ctx, user.ID)

	log.WithField("email", user.Email).
		WithField("session_id", session.SessionID).
		Info("User logged in successfully")

	return &models.LoginResponse{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		User:                  user.ToProfile(),
		SessionID:             session.SessionID,
	}, nil
}
