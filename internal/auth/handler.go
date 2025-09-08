package auth

import (
	"context"
	"errors"
	"fmt"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/session"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	cfg         *config.Configuration
	authService Service
}

func NewAuthHandler(cfg *config.Configuration, service Service) *Handler {
	return &Handler{
		cfg:         cfg,
		authService: service,
	}
}

func (h *Handler) Register(c *gin.Context) {
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
func (h *Handler) Login(c *gin.Context) {
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

func (h *Handler) VerifyEmail(c *gin.Context) {
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

func (h *Handler) ResetPassword(c *gin.Context) {
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
func (h *Handler) ResetPasswordConfirm(c *gin.Context) {
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
