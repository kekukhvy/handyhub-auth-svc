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
	log.WithField("email", req.Email).Info("Registering new user")

	if validationErrors := s.validator.ValidateRegisterRequest(req); validationErrors.HasErrors() {
		return nil, models.ErrInvalidRequest
	}

	s.validator.SanitizeRegisterRequest(req)

	isUnique, err := s.userService.IsEmailUnique(ctx, req.Email, nil)
	if err != nil {
		return nil, err
	}
	if !isUnique {
		return nil, models.ErrEmailAlreadyExists
	}

	user := req.ToUser()
	hashedPassword, err := utils.HashPassword(user.Password)
	if err != nil {
		return nil, models.ErrInternalServer
	}
	user.Password = hashedPassword

	createdUser, err := s.userService.CreateUser(ctx, user)
	if err != nil {
		return nil, err
	}

	s.userService.SendVerificationEmail(ctx, createdUser.ID)
	return createdUser, nil
}

func (s *authService) Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error) {
	user, err := s.validateLoginCredentials(ctx, req)
	if err != nil {
		return nil, err
	}

	ipAddress, userAgent := s.extractClientInfo(ctx)

	sessionReq := &models.SessionCreateRequest{
		UserID:      user.ID,
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
		ServiceName: "auth.service.Login",
		Action:      "session_created",
	}

	newSession, err := s.sessionManager.CreateSession(ctx, sessionReq)
	if err != nil {
		log.WithError(err).WithField("user_id", user.ID.Hex()).Error("Failed to create session")
		return nil, models.ErrSessionCreating
	}

	response, err := s.generateTokensAndUpdateSession(ctx, user, newSession, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	s.finalizeLogin(ctx, user, newSession)
	s.logLoginSuccess(user, newSession, ipAddress)
	return response, nil
}

func (s *authService) validateLoginCredentials(ctx context.Context, req *models.LoginRequest) (*models.User, error) {
	if validationErrors := s.validator.ValidateLoginRequest(req); validationErrors.HasErrors() {
		return nil, models.ErrInvalidCredentials
	}

	s.validator.SanitizeLoginRequest(req)

	if err := s.checkLoginRateLimit(ctx, req.Email); err != nil {
		return nil, err
	}

	user, err := s.userService.GetUserByEmail(ctx, req.Email)
	if err != nil {
		s.handleLoginFailure(ctx, req.Email)
		return nil, models.ErrInvalidCredentials
	}

	if !user.IsActive() {
		return nil, models.ErrUserInactive
	}

	if !utils.ComparePasswords(user.Password, req.Password) {
		s.handleLoginFailure(ctx, req.Email, user.ID)
		return nil, models.ErrInvalidCredentials
	}

	s.resetLoginRateLimit(ctx, req.Email)
	return user, nil
}

func (s *authService) extractClientInfo(ctx context.Context) (string, string) {
	ipAddress, _ := ctx.Value("client_ip").(string)
	userAgent, _ := ctx.Value("user_agent").(string)
	return ipAddress, userAgent
}

func (s *authService) generateTokensAndUpdateSession(ctx context.Context, user *models.User, session *models.Session, ipAddress, userAgent string) (*models.LoginResponse, error) {
	accessToken, accessExpiresAt, err := s.jwtManager.GenerateAccessToken(user.ID, session.SessionID, user.Email, user.Role)
	if err != nil {
		return nil, models.ErrTokenGenerating
	}

	refreshToken, refreshExpiresAt, err := s.jwtManager.GenerateRefreshToken(user.ID, session.SessionID)
	if err != nil {
		return nil, models.ErrTokenGenerating
	}

	session.RefreshToken = refreshToken
	session.AccessToken = accessToken
	session.ExpiresAt = refreshExpiresAt
	session.IPAddress = ipAddress
	session.UserAgent = userAgent

	s.sessionManager.Update(ctx, session)
	s.cacheService.CacheActiveSession(ctx, session)

	return &models.LoginResponse{
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		AccessTokenExpiresAt:  accessExpiresAt,
		RefreshTokenExpiresAt: refreshExpiresAt,
		User:                  user.ToProfile(),
		SessionID:             session.SessionID,
	}, nil
}

func (s *authService) finalizeLogin(ctx context.Context, user *models.User, session *models.Session) {
	s.userService.UpdateLastLogin(ctx, user.ID)

	updateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.Login",
		Action:      "login_completed",
	}
	s.sessionManager.UpdateActivity(updateReq)
}

func (s *authService) logLoginSuccess(user *models.User, session *models.Session, ipAddress string) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"user_id":     user.ID.Hex(),
		"session_id":  session.SessionID,
		"ip_address":  ipAddress,
		"device_type": deviceType,
	}).Info("User logged in successfully")
}

func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	if err := s.validateEmailToken(token); err != nil {
		return err
	}

	user, err := s.getUserByVerificationToken(ctx, token)
	if err != nil {
		return err
	}

	if err := s.checkVerificationEligibility(user); err != nil {
		return err
	}

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
	user, err := s.userService.GetUserByVerificationToken(ctx, token)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return nil, models.ErrVerificationTokenInvalid
		}
		return nil, err
	}
	return user, nil
}

func (s *authService) checkVerificationEligibility(user *models.User) error {
	if user.IsEmailVerified {
		return models.ErrEmailAlreadyVerified
	}

	if user.VerificationExpires != nil && time.Now().After(*user.VerificationExpires) {
		return models.ErrVerificationTokenExpired
	}
	return nil
}

func (s *authService) performEmailVerification(ctx context.Context, user *models.User) error {
	if err := s.userService.VerifyUserEmail(ctx, user.ID); err != nil {
		return err
	}

	s.cacheService.CacheUser(ctx, user, s.cfg.Cache.ExpirationMinutes)
	return nil
}

func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	if validationErrors := s.validator.ValidateResetPasswordRequest(&models.ResetPasswordRequest{Email: email}); validationErrors.HasErrors() {
		return models.ErrInvalidEmail
	}

	user, err := s.userService.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			log.WithField("email", email).Info("Password reset requested for non-existent email")
			return nil
		}
		return err
	}

	resetToken, _, err := s.jwtManager.GenerateResetToken(user.ID, user.Email)
	if err != nil {
		return models.ErrTokenGenerating
	}

	log.WithField("email", user.Email).Info("Password reset token generated")
	return s.userService.SendPasswordResetEmail(user, resetToken)
}

func (s *authService) ResetPassword(ctx context.Context, req *models.ResetPasswordConfirmRequest) error {
	if validationErrors := s.validator.ValidateResetPasswordConfirmRequest(req); validationErrors.HasErrors() {
		return models.ErrInvalidRequest
	}

	claims, err := s.jwtManager.ValidateResetToken(req.Token)
	if err != nil {
		return err
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return models.ErrInternalServer
	}

	err = s.userService.UpdatePassword(ctx, claims.UserID, hashedPassword)
	if err != nil {
		return err
	}

	s.invalidateAllUserSessions(ctx, claims.UserID, "auth.service.ResetPassword")

	log.WithField("email", claims.Email).Info("Password reset successfully")
	return nil
}

func (s *authService) VerifyToken(ctx context.Context, req *models.VerifyTokenRequest) (*models.VerifyTokenResponse, error) {
	if validationErrors := s.validator.ValidateVerifyTokenRequest(req); validationErrors.HasErrors() {
		return nil, models.ErrInvalidRequest
	}

	claims, err := s.validateTokenClaims(req.Token)
	if err != nil {
		return nil, err
	}

	userID, err := utils.GetUserIDFromClaims(claims)
	if err != nil {
		return nil, models.ErrInvalidToken
	}

	session, err := s.getAndValidateSession(ctx, claims.SessionID, userID)
	if err != nil {
		return nil, err
	}

	s.updateTokenVerificationActivity(ctx, session, userID, claims.SessionID)

	return &models.VerifyTokenResponse{
		Valid:     true,
		UserID:    userID,
		SessionID: claims.SessionID,
		ExpiresAt: claims.ExpiresAt.Time,
		IssuedAt:  claims.IssuedAt.Time,
	}, nil
}

// RefreshToken validates refresh token and generates new access token
func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*models.RefreshTokenResponse, error) {
	claims, err := s.validateRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	user, err := s.verifyUserForRefresh(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	session, err := s.getSessionForRefresh(ctx, refreshToken, user.ID)
	if err != nil {
		return nil, err
	}

	err = s.updateSessionForRefresh(ctx, session)
	if err != nil {
		return nil, err
	}

	response, err := s.generateNewTokens(ctx, user, session)
	if err != nil {
		return nil, err
	}

	s.logTokenRefreshSuccess(user, session)
	return response, nil
}

// getSessionForRefresh gets existing session or creates new one if expired
func (s *authService) getSessionForRefresh(ctx context.Context, refreshToken string, userID primitive.ObjectID) (*models.Session, error) {
	session, err := s.sessionManager.GetSessionByRefreshToken(ctx, refreshToken)
	if err != nil {
		log.WithError(err).Debug("Failed to find session by refresh token")
		return s.createNewSessionForRefresh(ctx, userID)
	}

	if session == nil {
		log.Debug("Session not found by refresh token, creating new session")
		return s.createNewSessionForRefresh(ctx, userID)
	}

	return session, nil
}

// createNewSessionForRefresh creates new session with current client info
func (s *authService) createNewSessionForRefresh(ctx context.Context, userID primitive.ObjectID) (*models.Session, error) {
	ipAddress, userAgent := s.extractClientInfo(ctx)

	sessionReq := &models.SessionCreateRequest{
		UserID:      userID,
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
		ServiceName: "auth.service.RefreshToken",
		Action:      "new_session_created",
	}

	session, err := s.sessionManager.CreateSession(ctx, sessionReq)
	if err != nil {
		log.WithError(err).Error("Failed to create new session for refresh")
		return nil, models.ErrSessionCreating
	}

	log.WithFields(logrus.Fields{
		"user_id":    userID.Hex(),
		"session_id": session.SessionID,
		"ip_address": ipAddress,
	}).Info("New session created for token refresh")

	return session, nil
}

// updateSessionForRefresh updates session with current client information
func (s *authService) updateSessionForRefresh(ctx context.Context, session *models.Session) error {
	ipAddress, userAgent := s.extractClientInfo(ctx)

	updateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.RefreshToken",
		Action:      "session_refreshed",
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	return s.sessionManager.RefreshSessionDetails(ctx, updateReq)
}

func (s *authService) ChangePassword(ctx context.Context, userID primitive.ObjectID, req *models.ChangePasswordRequest) error {
	if validationErrors := s.validator.ValidateChangePasswordRequest(req); validationErrors.HasErrors() {
		return models.ErrInvalidRequest
	}

	user, err := s.userService.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}

	if !utils.ComparePasswords(user.Password, req.CurrentPassword) {
		log.WithField("user_id", userID.Hex()).Warn("Invalid current password for password change")
		return models.ErrPasswordMismatch
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		return models.ErrInternalServer
	}

	err = s.userService.UpdatePassword(ctx, userID.Hex(), hashedPassword)
	if err != nil {
		return err
	}

	log.WithField("email", user.Email).Info("Password changed successfully")
	return nil
}

func (s *authService) Logout(ctx context.Context, sessionID string) error {
	session, err := s.sessionManager.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) {
			log.WithField("session_id", sessionID).Warn("Session not found during logout")
			return nil
		}
		return err
	}

	ipAddress, userAgent := s.extractClientInfo(ctx)

	invalidateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.Logout",
		Action:      "session_invalidated",
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	s.sessionManager.InvalidateSession(ctx, invalidateReq)
	s.cacheService.RemoveCachedSession(ctx, sessionID, session.UserID.Hex())

	s.logLogoutSuccess(session, ipAddress, userAgent)
	return nil
}

// Helper methods
func (s *authService) checkLoginRateLimit(ctx context.Context, email string) error {
	rateLimitKey := "login_attempts:" + email
	limited, err := s.cacheService.CheckRateLimit(ctx, rateLimitKey, s.cfg.Security.LoginRateLimit)

	if err == nil && limited {
		log.WithField("email", email).Warn("Login rate limit exceeded")
		return models.ErrLoginAttemptsExceeded
	}
	return nil
}

func (s *authService) handleLoginFailure(ctx context.Context, email string, userID ...primitive.ObjectID) {
	rateLimitKey := "login_attempts:" + email
	s.cacheService.IncrementRateLimit(ctx, rateLimitKey, 900)

	if len(userID) > 0 {
		s.userService.IncrementFailedLogin(ctx, userID[0])
	}

	log.WithField("email", email).Warn("Login attempt failed")
}

func (s *authService) resetLoginRateLimit(ctx context.Context, email string) {
	rateLimitKey := "login_attempts:" + email
	s.cacheService.ResetFailedLoginAttempts(ctx, rateLimitKey)
}

func (s *authService) validateTokenClaims(token string) (*utils.Claims, error) {
	claims, err := s.jwtManager.ValidateAccessToken(token)
	if err != nil {
		log.WithError(err).Debug("JWT validation failed")
		return nil, err
	}
	return claims, nil
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

func (s *authService) refreshSessionWithClientInfo(ctx context.Context, session *models.Session, ipAddress, userAgent string) error {
	updateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.RefreshToken",
		Action:      "session_refreshed",
		UserAgent:   userAgent,
		IPAddress:   ipAddress,
	}

	return s.sessionManager.RefreshSessionDetails(ctx, updateReq)
}

func (s *authService) generateNewTokens(ctx context.Context, user *models.User, session *models.Session) (*models.RefreshTokenResponse, error) {
	accessToken, accessExpiresAt, err := s.jwtManager.GenerateAccessToken(user.ID, session.SessionID, user.Email, user.Role)
	if err != nil {
		return nil, models.ErrTokenGenerating
	}

	session.AccessToken = accessToken
	session.ExpiresAt = time.Now().Add(time.Duration(s.cfg.Security.RefreshTokenExpiration) * time.Minute)

	s.sessionManager.Update(ctx, session)
	s.cacheService.CacheActiveSession(ctx, session)

	return &models.RefreshTokenResponse{
		AccessToken:          accessToken,
		AccessTokenExpiresAt: accessExpiresAt,
	}, nil
}

func (s *authService) getAndValidateSession(ctx context.Context, sessionID string, userID primitive.ObjectID) (*models.Session, error) {
	session, err := s.sessionManager.GetByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	validateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.VerifyToken",
		Action:      "session_validated",
	}

	isValid, err := s.sessionManager.ValidateSessionWithCache(ctx, validateReq)
	if err != nil {
		return nil, err
	}

	if !isValid {
		log.WithField("session_id", sessionID).Warn("Session is invalid or expired")
		return nil, models.ErrSessionExpired
	}

	return validateReq.Session, nil
}

func (s *authService) updateTokenVerificationActivity(ctx context.Context, session *models.Session, userID primitive.ObjectID, sessionID string) {
	updateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: "auth.service.VerifyToken",
		Action:      "token_verified",
	}
	s.sessionManager.UpdateActivity(updateReq)

	msg := models.ActivityMessage{
		UserID:      userID.Hex(),
		SessionID:   sessionID,
		Action:      "token_verified",
		ServiceName: "auth.service.VerifyToken",
		Timestamp:   time.Now(),
	}
	s.sessionManager.UpdateSessionActivity(ctx, &msg)
}

func (s *authService) invalidateAllUserSessions(ctx context.Context, userID, serviceName string) {
	id, _ := primitive.ObjectIDFromHex(userID)
	session := &models.Session{UserID: id}

	req := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: serviceName,
		Action:      "all_sessions_invalidated",
	}

	s.sessionManager.InvalidateUserSessions(ctx, req)
	s.cacheService.InvalidateUserSessions(ctx, userID)
}

func (s *authService) logTokenRefreshSuccess(user *models.User, session *models.Session) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"user_id":     user.ID.Hex(),
		"session_id":  session.SessionID,
		"ip_address":  session.IPAddress,
		"device_type": deviceType,
	}).Info("Token refreshed successfully")
}

func (s *authService) logLogoutSuccess(session *models.Session, ipAddress, userAgent string) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"session_id":  session.SessionID,
		"user_id":     session.UserID.Hex(),
		"ip_address":  ipAddress,
		"device_type": deviceType,
		"user_agent":  userAgent,
	}).Info("User logged out successfully")
}
