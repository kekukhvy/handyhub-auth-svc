package auth

import (
	"context"
	"errors"
	"fmt"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/session"
	"handyhub-auth-svc/internal/validators"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type handler struct {
	cfg            *config.Configuration
	authService    Service
	tokenValidator *validators.TokenValidator
}

type Handler interface {
	Register(c *gin.Context)
	Login(c *gin.Context)
	VerifyEmail(c *gin.Context)
	ResetPassword(c *gin.Context)
	ResetPasswordConfirm(c *gin.Context)
	VerifyToken(c *gin.Context)
	RefreshToken(c *gin.Context)
	ChangePassword(c *gin.Context)
	Logout(c *gin.Context)
}

func NewAuthHandler(cfg *config.Configuration, service Service, tokenValidator *validators.TokenValidator) Handler {
	return &handler{
		cfg:            cfg,
		authService:    service,
		tokenValidator: tokenValidator,
	}
}

func (h *handler) Register(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind register request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	// Register user
	user, err := h.authService.Register(ctx, &req)
	if err != nil {
		log.WithError(err).WithField("email", req.Email).Error("Registration failed")

		switch {
		case errors.Is(err, models.ErrEmailAlreadyExists):
			c.JSON(http.StatusConflict, models.NewErrorResponse(err, models.MessageEmailAlreadyExists))
		case errors.Is(err, models.ErrInvalidRequest):
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, models.MessageInvalidRequest))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.WithField("user_id", user.ID.Hex()).
		WithField("email", user.Email).
		Info("User registered successfully")

	c.JSON(http.StatusCreated, models.NewSuccessResponse(models.MessageRegistrationSuccess, user.ToProfile()))
}

// Login handles user authentication
func (h *handler) Login(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind login request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	// Extract client info for session
	ipAddress := session.ExtractIPAddress(c.Request)
	userAgent := session.ExtractUserAgent(c.Request)

	// Add client info to context for auth service
	c.Set("client_ip", ipAddress)
	c.Set("user_agent", userAgent)

	// Authenticate user
	loginResponse, err := h.authService.Login(ctx, &req)
	if err != nil {
		log.WithError(err).WithField("email", req.Email).Error("Login failed")

		switch err {
		case models.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, models.MessageInvalidCredentials))
		case models.ErrUserInactive:
			c.JSON(http.StatusForbidden, models.NewErrorResponse(err, models.MessageUserInactive))
		case models.ErrEmailNotVerified:
			c.JSON(http.StatusForbidden, models.NewErrorResponse(err, models.MessageEmailNotVerified))
		case models.ErrLoginAttemptsExceeded:
			c.JSON(http.StatusTooManyRequests, models.NewErrorResponse(err, "Too many login attempts. Please try again later."))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.WithField("user_id", loginResponse.User.ID.Hex()).
		WithField("session_id", loginResponse.SessionID).
		Info("User logged in successfully")

	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessageLoginSuccess, loginResponse))
}

func (h *handler) VerifyEmail(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	// Get token from query parameter
	token := c.Query("token")
	var endpoint = fmt.Sprintf("%s%s", h.cfg.Frontend.Url, h.cfg.Frontend.LoginPath)
	if token == "" {
		log.Error("Verification token not provided")
		// Redirect to frontend with error
		c.Redirect(http.StatusFound, "http://localhost:4200/login?error=missing_token&message=Verification+token+is+required")
		return
	}

	// Verify email using verification token
	err := h.authService.VerifyEmail(ctx, token)
	if err != nil {
		log.WithError(err).WithField("token", token[:min(10, len(token))]+"...").Error("Email verification failed")

		var redirectURL string
		switch {
		case errors.Is(err, models.ErrVerificationTokenInvalid):
			redirectURL = endpoint + "?error=invalid_token&message=Invalid+verification+token"
		case errors.Is(err, models.ErrVerificationTokenExpired):
			redirectURL = endpoint + "?error=token_expired&message=Verification+token+expired"
		case errors.Is(err, models.ErrEmailAlreadyVerified):
			redirectURL = endpoint + "?success=already_verified&message=Email+already+verified"
		case errors.Is(err, models.ErrUserNotFound):
			redirectURL = endpoint + "?error=user_not_found&message=User+not+found"
		default:
			redirectURL = endpoint + "?error=server_error&message=Internal+server+error"
		}

		c.Redirect(http.StatusFound, redirectURL)
		return
	}

	log.Info("Email verified successfully")
	c.Redirect(http.StatusFound, endpoint)
}

func (h *handler) ResetPassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind reset password request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	// Request password reset
	err := h.authService.RequestPasswordReset(ctx, req.Email)
	if err != nil {
		log.WithError(err).WithField("email", req.Email).Error("Password reset request failed")

		switch err {
		case models.ErrInvalidEmail:
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, "Invalid email address"))
		case models.ErrUserInactive:
			c.JSON(http.StatusForbidden, models.NewErrorResponse(err, models.MessageUserInactive))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.WithField("email", req.Email).Info("Password reset requested")
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessagePasswordResetSent, nil))
}

// ResetPasswordConfirm handles password reset confirmation
func (h *handler) ResetPasswordConfirm(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	var req models.ResetPasswordConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind reset password confirm request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	// Reset password
	err := h.authService.ResetPassword(ctx, &req)
	if err != nil {
		log.WithError(err).Error("Password reset failed")

		switch err {
		case models.ErrTokenExpired:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Reset token expired"))
		case models.ErrInvalidToken:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Invalid reset token"))
		case models.ErrUserNotFound:
			c.JSON(http.StatusNotFound, models.NewErrorResponse(err, models.MessageUserNotFound))
		case models.ErrInvalidRequest:
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, models.MessageInvalidRequest))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.Info("Password reset successfully")
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessagePasswordResetSuccess, nil))
}

func (h *handler) VerifyToken(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	// Extract token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Error("Authorization header is missing")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrInvalidToken,
			"Authorization header is required",
		))
		return
	}

	// Extract token from "Bearer <token>" format
	tokenValidator := validators.NewTokenValidator()
	token, err := tokenValidator.ExtractTokenFromHeader(authHeader)
	if err != nil {
		log.WithError(err).Error("Failed to extract token from header")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrInvalidToken,
			"Invalid authorization header format",
		))
		return
	}

	// Create request object for service
	req := &models.VerifyTokenRequest{
		Token: token,
	}

	// Verify token and session
	response, err := h.authService.VerifyToken(ctx, req)
	if err != nil {
		log.WithError(err).Error("Token verification failed")

		switch {
		case errors.Is(err, models.ErrInvalidToken), errors.Is(err, models.ErrTokenExpired):
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Invalid or expired token"))
		case errors.Is(err, models.ErrSessionExpired), errors.Is(err, models.ErrSessionInactive):
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, "Session expired or inactive"))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.WithField("user_id", response.UserID.Hex()).
		WithField("session_id", response.SessionID).
		Debug("Token verified successfully")

	c.JSON(http.StatusOK, models.NewSuccessResponse("Token is valid", response))
}

func (h *handler) RefreshToken(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	var req models.RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind refresh token request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	refreshResponse, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		log.WithError(err).Error("Token refresh failed")

		switch err {
		case models.ErrTokenExpired:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, models.MessageTokenExpired))
		case models.ErrInvalidToken:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, models.MessageTokenInvalid))
		case models.ErrSessionNotFound, models.ErrSessionExpired:
			c.JSON(http.StatusUnauthorized, models.NewErrorResponse(err, models.MessageSessionExpired))
		case models.ErrUserInactive:
			c.JSON(http.StatusForbidden, models.NewErrorResponse(err, models.MessageUserInactive))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.Info("Token refreshed successfully")
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessageTokenRefreshed, refreshResponse))
}

func (h *handler) ChangePassword(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	// Get user ID from middleware
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		log.Error("User ID not found in context")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrUnauthorized,
			"User not authenticated",
		))
		return
	}

	userIDStr, ok := userIDInterface.(string)
	if !ok {
		log.Error("Invalid user ID format")
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(
			models.ErrInternalServer,
			"Invalid user ID format",
		))
		return
	}

	userID, err := primitive.ObjectIDFromHex(userIDStr)
	if err != nil {
		log.WithError(err).Error("Failed to parse user ID")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidUserID,
			"Invalid user ID",
		))
		return
	}

	var req models.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind change password request")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Invalid request format",
		))
		return
	}

	err = h.authService.ChangePassword(ctx, userID, &req)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Password change failed")

		switch err {
		case models.ErrPasswordMismatch:
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, "Current password is incorrect"))
		case models.ErrInvalidRequest:
			c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, models.MessageInvalidRequest))
		case models.ErrUserNotFound:
			c.JSON(http.StatusNotFound, models.NewErrorResponse(err, models.MessageUserNotFound))
		default:
			c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		}
		return
	}

	log.WithField("user_id", userID.Hex()).Info("Password changed successfully")
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessagePasswordChangeSuccess, nil))
}

func (h *handler) Logout(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	// Get session ID from middleware
	sessionID, exists := c.Get("session_id")
	if !exists {
		log.Error("Session ID not found in context")
		c.JSON(http.StatusUnauthorized, models.NewErrorResponse(
			models.ErrSessionNotFound,
			"Session not found",
		))
		return
	}

	sessionIDStr, ok := sessionID.(string)
	if !ok {
		log.Error("Invalid session ID format")
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(
			models.ErrSessionInvalid,
			"Invalid session format",
		))
		return
	}

	// Logout user
	err := h.authService.Logout(ctx, sessionIDStr)
	if err != nil {
		log.WithError(err).WithField("session_id", sessionIDStr).Error("Logout failed")
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, models.MessageInternalError))
		return
	}

	log.WithField("session_id", sessionIDStr).Info("User logged out successfully")
	c.JSON(http.StatusOK, models.NewSuccessResponse(models.MessageLogoutSuccess, nil))
}
