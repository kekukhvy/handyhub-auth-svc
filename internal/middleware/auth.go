package middleware

import (
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/user"
	"handyhub-auth-svc/internal/utils"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var log = logrus.StandardLogger()

type AuthMiddleware struct {
	jwtManager     *utils.JWTManager
	sessionService session.Manager
	userService    user.Service
}

func NewAuthMiddleware(
	jwtManager *utils.JWTManager,
	sessionService session.Manager,
	userService user.Service) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:     jwtManager,
		sessionService: sessionService,
		userService:    userService,
	}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := m.authenticateRequest(c)
		if err != nil {
			return
		}

		userSession, err := m.validateUserSession(c, claims)
		if err != nil {
			return
		}

		m.updateSessionActivity(c, userSession, claims)
		m.setUserContext(c, claims)

		m.logAuthSuccess(claims, userSession)
		c.Next()
	}
}

func (m *AuthMiddleware) authenticateRequest(c *gin.Context) (*utils.Claims, error) {
	token, err := m.extractToken(c)
	if err != nil {
		log.WithError(err).Error("Failed to extract token")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrUnauthorized,
			"Authorization token is required",
		))
		c.Abort()
		return nil, err
	}

	claims, err := m.jwtManager.ValidateAccessToken(token)
	if err != nil {
		log.WithError(err).Error("Invalid access token")
		m.handleTokenValidationError(c, err)
		c.Abort()
		return nil, err
	}

	return claims, nil
}

func (m *AuthMiddleware) handleTokenValidationError(c *gin.Context, err error) {
	switch err {
	case models.ErrTokenExpired:
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Token expired"))
	case models.ErrInvalidToken:
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Invalid token"))
	default:
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Token validation failed"))
	}
}

func (m *AuthMiddleware) validateUserSession(c *gin.Context, claims *utils.Claims) (*models.Session, error) {
	_, err := utils.GetUserIDFromClaims(claims)
	if err != nil {
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrInvalidToken,
			"Invalid user ID in token",
		))
		c.Abort()
		return nil, err
	}

	userSession, err := m.sessionService.GetByID(c.Request.Context(), claims.SessionID)
	if err != nil {
		log.WithError(err).WithField("session_id", claims.SessionID).Error("Failed to retrieve session")
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(
			models.ErrInternalServer,
			"Session retrieval error",
		))
		c.Abort()
		return nil, err
	}

	validateReq := &models.SessionUpdateRequest{
		Session:     userSession,
		ServiceName: "auth.middleware.RequireAuth",
		Action:      "session_validation",
		UserAgent:   c.Request.UserAgent(),
		IPAddress:   c.ClientIP(),
	}

	isValid, err := m.sessionService.ValidateSessionWithCache(c.Request.Context(), validateReq)
	if err != nil || !isValid {
		log.WithField("session_id", claims.SessionID).Warn("Invalid or expired session")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrSessionExpired,
			"Session expired or invalid",
		))
		c.Abort()
		return nil, models.ErrSessionExpired
	}

	return validateReq.Session, nil
}

func (m *AuthMiddleware) updateSessionActivity(c *gin.Context, userSession *models.Session, claims *utils.Claims) {
	updateReq := &models.SessionUpdateRequest{
		Session:     userSession,
		ServiceName: "auth.middleware.RequireAuth",
		Action:      "authenticated",
		UserAgent:   c.Request.UserAgent(),
		IPAddress:   c.ClientIP(),
	}

	m.sessionService.UpdateActivity(updateReq)

	msg := &models.ActivityMessage{
		UserID:      claims.UserID,
		SessionID:   claims.SessionID,
		ServiceName: "auth.middleware.RequireAuth",
		Action:      "authenticated",
		UserAgent:   c.Request.UserAgent(),
		IPAddress:   c.ClientIP(),
		Timestamp:   time.Now(),
	}

	if err := m.sessionService.UpdateSessionActivity(c.Request.Context(), msg); err != nil {
		log.WithError(err).WithField("session_id", claims.SessionID).Warn("Failed to update session activity")
	}
}

func (m *AuthMiddleware) setUserContext(c *gin.Context, claims *utils.Claims) {
	c.Set("user_id", claims.UserID)
	c.Set("session_id", claims.SessionID)
	c.Set("user_email", claims.Email)
	c.Set("user_role", claims.Role)
}

func (m *AuthMiddleware) logAuthSuccess(claims *utils.Claims, userSession *models.Session) {
	deviceType := "unknown"
	if userSession.DeviceInfo != nil {
		deviceType = userSession.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"user_id":     claims.UserID,
		"session_id":  claims.SessionID,
		"ip_address":  userSession.IPAddress,
		"device_type": deviceType,
		"service":     "auth.middleware.RequireAuth",
		"action":      "authenticated",
	}).Debug("User authenticated successfully")
}

func (m *AuthMiddleware) extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", models.ErrInvalidToken
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", models.ErrInvalidToken
	}

	token := parts[1]
	if token == "" {
		return "", models.ErrInvalidToken
	}

	return token, nil
}
