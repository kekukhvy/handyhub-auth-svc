package middleware

import (
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/user"
	"handyhub-auth-svc/internal/utils"
	"net/http"
	"strings"

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
		// Extract token from Authorization header
		token, err := m.extractToken(c)
		if err != nil {
			log.WithError(err).Error("Failed to extract token")
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
				models.ErrUnauthorized,
				"Authorization token is required",
			))
			c.Abort()
			return
		}

		// Validate JWT token
		claims, err := m.jwtManager.ValidateAccessToken(token)
		if err != nil {
			log.WithError(err).Error("Invalid access token")

			switch err {
			case models.ErrTokenExpired:
				c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Token expired"))
			case models.ErrInvalidToken:
				c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Invalid token"))
			default:
				c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Token validation failed"))
			}
			c.Abort()
			return
		}

		session, err := m.sessionService.GetByID(c.Request.Context(), claims.SessionID)
		if err != nil {
			log.WithError(err).WithField("session_id", claims.SessionID).Error("Failed to retrieve session")
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(
				models.ErrInternalServer,
				"Session retrieval error",
			))
			c.Abort()
			return
		}
		// Validate session
		isValid := m.sessionService.IsSessionValid(session)

		if !isValid {
			log.WithField("session_id", claims.SessionID).Warn("Invalid session")
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
				models.ErrSessionExpired,
				"Session expired or invalid",
			))
			c.Abort()
			return
		}

		// Update session activity
		if err := m.sessionService.UpdateSessionActivity(c.Request.Context(), claims.SessionID); err != nil {
			log.WithError(err).WithField("session_id", claims.SessionID).Warn("Failed to update session activity")
			// Not critical, continue
		}

		// Store user information in context
		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)
		c.Set("user_email", claims.Email)
		c.Set("user_role", claims.Role)

		log.WithField("user_id", claims.UserID).
			WithField("session_id", claims.SessionID).
			Debug("User authenticated successfully")

		c.Next()
	}
}

func (m *AuthMiddleware) extractToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", models.ErrInvalidToken
	}

	// Check Bearer format
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
