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
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Service interface {
	// Authentication operations
	Register(ctx context.Context, req *models.RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error)
	VerifyEmail(ctx context.Context, token string) error
	RequestPasswordReset(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, req *models.ResetPasswordConfirmRequest) error
	VerifyToken(ctx context.Context, req *models.VerifyTokenRequest) (*models.VerifyTokenResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*models.RefreshTokenResponse, error)
	ChangePassword(ctx context.Context, userID primitive.ObjectID, req *models.ChangePasswordRequest) error
	Logout(ctx context.Context, sessionID string) error
}

var log = logrus.StandardLogger()

type authService struct {
	validator      *validators.RequestValidator
	userService    user.Service
	sessionManager session.Manager
	cfg            *config.Configuration
	jwtManager     *utils.JWTManager
	cacheService   cache.Service
}

func NewAuthService(validator *validators.RequestValidator, userService user.Service,
	cfg *config.Configuration, sessionManager session.Manager, cacheService cache.Service,
	jwtManager *utils.JWTManager) Service {
	return &authService{
		validator:      validator,
		userService:    userService,
		cfg:            cfg,
		sessionManager: sessionManager,
		cacheService:   cacheService,
		jwtManager:     jwtManager,
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

	err = s.userService.SendVerificationEmail(ctx, createdUser.ID)
	if err != nil {
		log.WithError(err).WithField("user_id", createdUser.ID.Hex()).Error("Failed to send verification email")
	}

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

	ipAddress, _ := ctx.Value("client_ip").(string)
	userAgent, _ := ctx.Value("user_agent").(string)

	// Create session (IP and UserAgent would be passed from handler)
	session, err := s.sessionManager.CreateSession(ctx, user.ID, userAgent, ipAddress)
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
	session.ExpiresAt = refreshExpiresAt
	session.IPAddress = ipAddress
	session.UserAgent = userAgent

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

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	// Validate and sanitize token
	if err := s.validateEmailToken(token); err != nil {
		return err
	}

	// Get user by verification token
	user, err := s.getUserByVerificationToken(ctx, token)
	if err != nil {
		return err
	}

	// Check verification status and expiration
	if err := s.checkVerificationEligibility(user); err != nil {
		return err
	}

	// Perform email verification
	if err := s.performEmailVerification(ctx, user); err != nil {
		return err
	}

	log.WithField("email", user.Email).Info("Email verified successfully")
	return nil
}

func (s *authService) validateEmailToken(token string) error {
	if len(token) == 0 {
		return models.ErrVerificationTokenInvalid
	}

	token = strings.TrimSpace(token)
	if len(token) < 10 {
		return models.ErrVerificationTokenInvalid
	}
	return nil
}

func (s *authService) getUserByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	log.WithField("token_prefix", token[:min(10, len(token))]+"...").Info("Verifying email with token")

	user, err := s.userService.GetUserByVerificationToken(ctx, token)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			log.Warn("Verification token not found or invalid")
			return nil, models.ErrVerificationTokenInvalid
		}
		log.WithError(err).Error("Failed to get user by verification token")
		return nil, err
	}
	return user, nil
}

func (s *authService) checkVerificationEligibility(user *models.User) error {
	if user.IsEmailVerified {
		log.WithField("email", user.Email).Warn("Email already verified")
		return models.ErrEmailAlreadyVerified
	}

	if user.VerificationExpires != nil && time.Now().After(*user.VerificationExpires) {
		log.WithField("email", user.Email).Warn("Verification token expired")
		return models.ErrVerificationTokenExpired
	}
	return nil
}

func (s *authService) performEmailVerification(ctx context.Context, user *models.User) error {
	if err := s.userService.VerifyUserEmail(ctx, user.ID); err != nil {
		log.WithError(err).WithField("user_id", user.ID.Hex()).Error("Failed to verify user email")
		return err
	}

	// Update user cache after verification
	s.cacheService.CacheUser(ctx, user, s.cfg.Cache.ExpirationMinutes)
	return nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	// Validate email format
	if validationErrors := s.validator.ValidateResetPasswordRequest(&models.ResetPasswordRequest{Email: email}); validationErrors.HasErrors() {
		return models.ErrInvalidEmail
	}

	// Get user by email
	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			// Don't reveal if email exists or not
			log.WithField("email", email).Info("Password reset requested for non-existent email")
			return nil
		}
		return err
	}

	resetToken, _, err := s.jwtManager.GenerateResetToken(user.ID, user.Email)
	if err != nil {
		log.WithError(err).Error("Failed to generate reset token")
		return models.ErrTokenGenerating
	}

	log.WithField("email", user.Email).
		WithField("reset_token", resetToken).
		Info("Password reset token generated")

	return s.userService.SendPasswordResetEmail(user, resetToken)
}

func (s *authService) ResetPassword(ctx context.Context, req *models.ResetPasswordConfirmRequest) error {
	// Validate request
	if validationErrors := s.validator.ValidateResetPasswordConfirmRequest(req); validationErrors.HasErrors() {
		return models.ErrInvalidRequest
	}

	// Validate reset token
	claims, err := s.jwtManager.ValidateResetToken(req.Token)
	if err != nil {
		log.WithError(err).Error("Invalid reset token")
		return err
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.WithError(err).Error("Failed to hash new password")
		return models.ErrInternalServer
	}

	// Update password
	err = s.userService.UpdatePassword(ctx, claims.UserID, hashedPassword)
	if err != nil {
		return err
	}

	// Invalidate all user sessions for security
	s.InvalidateAllUserSessions(ctx, claims.UserID)

	log.WithField("email", claims.Email).Info("Password reset successfully")

	return nil
}

func (s *authService) InvalidateAllUserSessions(ctx context.Context, userID string) error {
	err := s.sessionManager.InvalidateUserSessions(ctx, userID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to invalidate user sessions")
		return err
	}

	err = s.cacheService.InvalidateUserSessions(ctx, userID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to invalidate user sessions in cache")
		return err
	}
	return nil
}
func (s *authService) VerifyToken(ctx context.Context, req *models.VerifyTokenRequest) (*models.VerifyTokenResponse, error) {
	// Validate request
	if validationErrors := s.validator.ValidateVerifyTokenRequest(req); validationErrors.HasErrors() {
		return nil, models.ErrInvalidRequest
	}

	// Parse and validate JWT token
	claims, err := s.validateTokenClaims(req.Token)
	if err != nil {
		return nil, err
	}

	// Validate session
	userID, err := s.validateUserSession(ctx, claims)
	if err != nil {
		return nil, err
	}

	// Update session activity
	s.updateTokenActivity(ctx, userID, claims.SessionID)

	return &models.VerifyTokenResponse{
		Valid:     true,
		UserID:    userID,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
	}, nil
}

func (s *authService) validateTokenClaims(token string) (*utils.Claims, error) {
	log.WithField("token_prefix", token[:min(10, len(token))]+"...").Debug("Validating token claims")

	claims, err := s.jwtManager.ValidateAccessToken(token)
	if err != nil {
		log.WithError(err).Debug("JWT validation failed")
		return nil, err
	}
	return claims, nil
}

func (s *authService) validateUserSession(ctx context.Context, claims *utils.Claims) (primitive.ObjectID, error) {
	userID, err := utils.GetUserIDFromClaims(claims)
	if err != nil {
		log.WithError(err).Error("Invalid user ID in token")
		return primitive.NilObjectID, models.ErrInvalidToken
	}

	isValid, err := s.sessionManager.ValidateSessionWithCache(ctx, claims.SessionID, userID)
	if err != nil {
		log.WithError(err).WithField("session_id", claims.SessionID).Error("Session validation failed")
		return primitive.NilObjectID, err
	}

	if !isValid {
		log.WithField("session_id", claims.SessionID).Warn("Session is invalid or expired")
		return primitive.NilObjectID, models.ErrSessionExpired
	}

	return userID, nil
}

func (s *authService) updateTokenActivity(ctx context.Context, userID primitive.ObjectID, sessionID string) {
	msg := models.ActivityMessage{
		UserID:      userID.Hex(),
		SessionID:   sessionID,
		Action:      "token_verified",
		ServiceName: "auth_service",
		Timestamp:   time.Now(),
	}
	s.sessionManager.UpdateSessionActivity(ctx, &msg)
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*models.RefreshTokenResponse, error) {
	// Validate and parse refresh token
	claims, err := s.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	// Verify user eligibility
	user, err := s.verifyUserForRefresh(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	// Get or create session
	session, err := s.getOrCreateSession(ctx, refreshToken, user.ID)
	if err != nil {
		return nil, err
	}

	// Generate new tokens and update session
	response, err := s.generateTokensAndUpdateSession(ctx, user, session)
	if err != nil {
		return nil, err
	}

	log.WithField("user_id", user.ID.Hex()).
		WithField("session_id", session.SessionID).
		Info("Token refreshed successfully")

	return response, nil
}

func (s *authService) validateRefreshToken(refreshToken string) (*utils.Claims, error) {
	if validationErrors := s.validator.ValidateRefreshTokenRequest(&models.RefreshTokenRequest{RefreshToken: refreshToken}); validationErrors.HasErrors() {
		return nil, models.ErrInvalidToken
	}

	claims, err := s.jwtManager.ValidateRefreshToken(refreshToken)
	if err != nil {
		log.WithError(err).Error("Invalid refresh token")
		return nil, err
	}
	return claims, nil
}

func (s *authService) verifyUserForRefresh(ctx context.Context, userIDStr string) (*models.User, error) {
	userID, _ := primitive.ObjectIDFromHex(userIDStr)
	user, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if !user.IsActive() {
		log.WithField("user_id", user.ID.Hex()).Warn("Inactive user token refresh attempt")
		return nil, models.ErrUserInactive
	}
	return user, nil
}

func (s *authService) getOrCreateSession(ctx context.Context, refreshToken string, userID primitive.ObjectID) (*models.Session, error) {
	session, err := s.sessionManager.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		log.WithError(err).Error("Failed to find session by refresh token")
	}

	if session == nil {
		session, err = s.sessionManager.CreateSession(ctx, userID, "", "")
		if err != nil {
			log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to create new session during refresh")
			return nil, models.ErrSessionCreating
		}
	}
	return session, nil
}

func (s *authService) generateTokensAndUpdateSession(ctx context.Context, user *models.User, session *models.Session) (*models.RefreshTokenResponse, error) {
	accessToken, accessExpiresAt, err := s.jwtManager.GenerateAccessToken(user.ID, session.SessionID, user.Email, user.Role)
	if err != nil {
		log.WithError(err).Error("Failed to generate new access token")
		return nil, models.ErrTokenGenerating
	}

	session.AccessToken = accessToken
	session.ExpiresAt = time.Now().Add(time.Duration(s.cfg.Security.RefreshTokenExpiration))

	s.sessionManager.Update(ctx, session)
	s.cacheService.CacheActiveSession(ctx, session)

	return &models.RefreshTokenResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessExpiresAt,
	}, nil
}

func (s *authService) ChangePassword(ctx context.Context, userID primitive.ObjectID, req *models.ChangePasswordRequest) error {
	// Validate request
	if validationErrors := s.validator.ValidateChangePasswordRequest(req); validationErrors.HasErrors() {
		return models.ErrInvalidRequest
	}

	// Get user
	user, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify current password
	if !utils.ComparePasswords(user.Password, req.CurrentPassword) {
		log.WithField("user_id", userID.Hex()).Warn("Invalid current password for password change")
		return models.ErrPasswordMismatch
	}

	// Hash new password
	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.WithError(err).Error("Failed to hash new password")
		return models.ErrInternalServer
	}

	// Update password
	err = s.userService.UpdatePassword(ctx, userID.Hex(), hashedPassword)
	if err != nil {
		return err
	}

	log.WithField("email", user.Email).Info("Password changed successfully")

	return nil
}

func (s *authService) Logout(ctx context.Context, sessionID string) error {
	// Get session
	session, err := s.sessionManager.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) {
			// Session might already be invalidated, not an error
			log.WithField("session_id", sessionID).Warn("Session not found during logout")
			return nil
		}
		return err
	}

	s.sessionManager.InvalidateSession(ctx, session)

	s.cacheService.RemoveCachedSession(ctx, sessionID, session.UserID.Hex())

	log.WithField("session_id", sessionID).
		WithField("user_id", session.UserID.Hex()).
		Info("User logged out successfully")

	return nil
}
