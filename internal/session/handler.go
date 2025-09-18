package session

import (
	"context"
	"net/http"
	"time"

	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/validators"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Handler interface {
	GetSessionById(c *gin.Context)
}

type handler struct {
	cfg            *config.Configuration
	sessionManager Manager
	validator      *validators.RequestValidator
}

func NewSessionHandler(cfg *config.Configuration, sessionManager Manager, validator *validators.RequestValidator) Handler {
	return &handler{
		cfg:            cfg,
		sessionManager: sessionManager,
		validator:      validator,
	}
}

func (h *handler) GetSessionById(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), time.Duration(h.cfg.App.Timeout)*time.Second)
	defer cancel()

	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidSessionID,
			"Session ID is required",
		))
		return
	}

	// Create request object for validation
	req := models.GetSessionByIdRequest{
		SessionID:   sessionID,
		ServiceName: "GetSessionById",
		Action:      "session_check",
	}

	// Validate and sanitize request
	if validationErrors := h.validator.ValidateAndSanitizeGetSessionRequest(&req); validationErrors.HasErrors() {
		log.WithField("errors", validationErrors.Errors).Error("Get session validation failed")
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(
			models.ErrInvalidRequest,
			"Validation failed",
		))
		return
	}

	// Set default values if not provided
	if req.Action == "" {
		req.Action = "session_check"
	}

	sessionReq := &models.SessionGetRequest{
		SessionID:   req.SessionID,
		ServiceName: req.ServiceName,
		Action:      req.Action,
	}

	sessionInfo, err := h.sessionManager.GetSessionById(ctx, sessionReq)
	if err != nil {
		h.handleGetSessionError(c, err, req.SessionID, req.ServiceName)
		return
	}

	response := &models.GetSessionByIdResponse{
		Session: sessionInfo,
		Status:  "success",
		Message: "Session retrieved successfully",
	}

	h.logSessionRetrieved(sessionInfo, req.ServiceName)
	c.JSON(http.StatusOK, response)
}

func (h *handler) handleGetSessionError(c *gin.Context, err error, sessionID, serviceName string) {
	log.WithError(err).WithFields(logrus.Fields{
		"session_id": sessionID,
		"service":    serviceName,
	}).Error("Failed to get session")

	switch err {
	case models.ErrSessionNotFound:
		c.JSON(http.StatusNotFound, models.NewErrorResponse(err, "Session not found"))
	case models.ErrInvalidSessionID:
		c.JSON(http.StatusBadRequest, models.NewErrorResponse(err, "Invalid session ID"))
	default:
		c.JSON(http.StatusInternalServerError, models.NewErrorResponse(err, "Internal server error"))
	}
}

func (h *handler) logSessionRetrieved(sessionInfo *models.SessionInfo, serviceName string) {
	log.WithFields(logrus.Fields{
		"session_id":         sessionInfo.SessionID,
		"user_id":            sessionInfo.UserID.Hex(),
		"requesting_service": serviceName,
		"is_valid":           sessionInfo.IsValid,
		"is_active":          sessionInfo.IsActive,
		"device_type":        sessionInfo.DeviceType,
		"ip_address":         sessionInfo.IPAddress,
		"last_service":       sessionInfo.LastService,
		"last_action":        sessionInfo.LastAction,
	}).Info("Session information provided to external service")
}
