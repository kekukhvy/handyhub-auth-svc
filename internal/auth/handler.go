package auth

import (
	"context"
	"errors"
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
