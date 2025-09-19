package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var log = logrus.StandardLogger()

type Manager interface {
	CreateSession(ctx context.Context, req *models.SessionCreateRequest) (*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
	ValidateSession(session *models.Session) *models.SessionStatus
	GetByID(ctx context.Context, sessionID string) (*models.Session, error)
	GetSessionById(ctx context.Context, req *models.SessionGetRequest) (*models.SessionInfo, error)
	IsSessionValid(session *models.Session) bool
	UpdateActivity(req *models.SessionUpdateRequest)
	InvalidateSession(ctx context.Context, req *models.SessionUpdateRequest)
	IsRefreshTokenValid(session *models.Session, refreshToken string) bool
	GetSessionAge(session *models.Session) map[string]int64
	GetTimeUntilExpiry(session *models.Session) time.Duration
	InvalidateUserSessions(ctx context.Context, req *models.SessionUpdateRequest) error
	ValidateSessionWithCache(ctx context.Context, req *models.SessionUpdateRequest) (bool, error)
	GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	UpdateSessionActivity(ctx context.Context, msg *models.ActivityMessage) error
	RefreshSessionDetails(ctx context.Context, req *models.SessionUpdateRequest) error
}

type manager struct {
	repository   Repository
	cacheService cache.Service
	cfg          *config.Configuration
}

func NewManager(db *clients.MongoDB, cfg *config.Configuration, cacheService cache.Service) Manager {
	return &manager{
		repository:   NewSessionRepository(db, cfg.Database.Collections.Sessions),
		cacheService: cacheService,
		cfg:          cfg,
	}
}

// CreateSession creates a new session with full details
func (m *manager) CreateSession(ctx context.Context, req *models.SessionCreateRequest) (*models.Session, error) {
	now := time.Now()
	sessionID := m.generateSessionID()
	deviceInfo := ParseDeviceInfo(req.UserAgent)

	session := &models.Session{
		SessionID:    sessionID,
		UserID:       req.UserID,
		UserAgent:    req.UserAgent,
		IPAddress:    req.IPAddress,
		CreatedAt:    now,
		LastActiveAt: now,
		LastService:  req.ServiceName,
		LastAction:   []models.ActionHistoryItem{},
		IsActive:     true,
		DeviceInfo:   deviceInfo,
	}

	// Add initial action to session history
	session.AddAction(req.Action)

	m.logSessionCreation(req.UserID, sessionID, req.IPAddress, deviceInfo, req.ServiceName, req.Action)

	session, err := m.repository.Create(ctx, session)
	if err != nil {
		log.WithError(err).WithField("user_id", req.UserID.Hex()).Error("Failed to create session")
		return nil, err
	}

	log.WithField("session_id", sessionID).Info("Session created successfully")
	return session, nil
}

func (m *manager) logSessionCreation(userID primitive.ObjectID, sessionID, ipAddress string, deviceInfo *models.DeviceInfo, serviceName, action string) {
	log.WithFields(logrus.Fields{
		"user_id":     userID.Hex(),
		"session_id":  sessionID,
		"ip_address":  ipAddress,
		"device_type": deviceInfo.DeviceType,
		"os":          deviceInfo.OS,
		"browser":     deviceInfo.Browser,
		"service":     serviceName,
		"action":      action,
	}).Info("Creating session with details")
}

func (m *manager) Update(ctx context.Context, session *models.Session) error {
	session.LastActiveAt = time.Now()

	log.WithFields(logrus.Fields{
		"session_id":   session.SessionID,
		"user_id":      session.UserID.Hex(),
		"last_service": session.LastService,
		"last_action":  session.LastAction,
		"is_active":    session.IsActive,
	}).Debug("Updating session")

	return m.repository.Update(ctx, session)
}

func (m *manager) ValidateSession(session *models.Session) *models.SessionStatus {
	if session == nil {
		return &models.SessionStatus{
			IsValid:  false,
			IsActive: false,
		}
	}
	return session.ToSessionStatus()
}

func (m *manager) GetByID(ctx context.Context, sessionID string) (*models.Session, error) {
	return m.repository.GetByID(ctx, sessionID)
}

func (m *manager) GetSessionById(ctx context.Context, req *models.SessionGetRequest) (*models.SessionInfo, error) {
	log.WithFields(logrus.Fields{
		"session_id": req.SessionID,
		"service":    req.ServiceName,
		"action":     req.Action,
	}).Debug("Getting session by ID for external service")

	session, err := m.repository.GetByID(ctx, req.SessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) {
			return nil, models.ErrSessionNotFound
		}
		log.WithError(err).WithField("session_id", req.SessionID).Error("Failed to get session by ID")
		return nil, err
	}

	sessionInfo := m.buildSessionInfo(session)

	// Update session activity for audit trail
	m.updateSessionActivityForExternalCheck(session, req.ServiceName, req.Action)

	m.logExternalSessionCheck(session, sessionInfo, req.ServiceName)
	return sessionInfo, nil
}

func (m *manager) buildSessionInfo(session *models.Session) *models.SessionInfo {
	deviceType := "unknown"
	os := "unknown"
	browser := "unknown"

	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
		os = session.DeviceInfo.OS
		browser = session.DeviceInfo.Browser
	}

	return &models.SessionInfo{
		SessionID:    session.SessionID,
		UserID:       session.UserID,
		IsActive:     session.IsActive,
		IsValid:      session.IsValidSession(),
		CreatedAt:    session.CreatedAt,
		ExpiresAt:    session.ExpiresAt,
		LastActiveAt: session.LastActiveAt,
		IPAddress:    session.IPAddress,
		DeviceType:   deviceType,
		OS:           os,
		Browser:      browser,
		LastService:  session.LastService,
		LastAction:   session.LastAction,
		LogoutAt:     session.LogoutAt,
	}
}

func (m *manager) updateSessionActivityForExternalCheck(session *models.Session, serviceName, action string) {
	updateReq := &models.SessionUpdateRequest{
		Session:     session,
		ServiceName: serviceName,
		Action:      action,
	}
	m.UpdateActivity(updateReq)
}

func (m *manager) logExternalSessionCheck(session *models.Session, sessionInfo *models.SessionInfo, serviceName string) {
	log.WithFields(logrus.Fields{
		"session_id":         session.SessionID,
		"user_id":            session.UserID.Hex(),
		"is_valid":           sessionInfo.IsValid,
		"is_active":          sessionInfo.IsActive,
		"device_type":        sessionInfo.DeviceType,
		"ip_address":         sessionInfo.IPAddress,
		"requesting_service": serviceName,
		"last_service":       session.LastService,
		"last_action":        session.LastAction,
	}).Info("Session retrieved for external service")
}

func (m *manager) IsSessionValid(session *models.Session) bool {
	if session == nil {
		return false
	}
	return session.IsValidSession()
}

// UpdateActivity updates session with activity details
func (m *manager) UpdateActivity(req *models.SessionUpdateRequest) {
	if req.Session == nil {
		return
	}

	req.Session.UpdateActivity()
	req.Session.LastService = req.ServiceName

	req.Session.AddAction(req.Action)

	m.updateClientInfo(req.Session, req.UserAgent, req.IPAddress)

	log.WithFields(logrus.Fields{
		"session_id": req.Session.SessionID,
		"service":    req.ServiceName,
		"action":     req.Action,
	}).Debug("Updated session activity")
}

func (m *manager) updateClientInfo(session *models.Session, userAgent, ipAddress string) {
	if ipAddress != "" && ipAddress != session.IPAddress {
		session.IPAddress = ipAddress
	}

	if userAgent != "" && userAgent != session.UserAgent {
		session.UserAgent = userAgent
		session.DeviceInfo = ParseDeviceInfo(userAgent)
	}
}

// InvalidateSession marks session as inactive with details
func (m *manager) InvalidateSession(ctx context.Context, req *models.SessionUpdateRequest) {
	if req.Session == nil {
		return
	}

	req.Session.Logout() // This will call AddAction("session_logged_out") internally
	req.Session.LastService = req.ServiceName

	m.updateClientInfo(req.Session, req.UserAgent, req.IPAddress)

	log.WithFields(logrus.Fields{
		"session_id": req.Session.SessionID,
		"user_id":    req.Session.UserID.Hex(),
		"service":    req.ServiceName,
		"action":     req.Action,
	}).Info("Invalidating session")

	m.repository.Update(ctx, req.Session)
}

func (m *manager) IsRefreshTokenValid(session *models.Session, refreshToken string) bool {
	if session == nil {
		return false
	}

	if !session.IsValidSession() {
		return false
	}

	return session.RefreshToken == refreshToken
}

func (m *manager) GetSessionAge(session *models.Session) map[string]int64 {
	if session == nil {
		return map[string]int64{
			"seconds": 0,
			"minutes": 0,
			"hours":   0,
			"days":    0,
		}
	}

	age := time.Since(session.CreatedAt)
	return map[string]int64{
		"seconds": int64(age.Seconds()),
		"minutes": int64(age.Minutes()),
		"hours":   int64(age.Hours()),
		"days":    int64(age.Hours() / 24),
	}
}

func (m *manager) GetTimeUntilExpiry(session *models.Session) time.Duration {
	if session == nil {
		return 0
	}
	return session.GetTimeUntilExpiry()
}

func (m *manager) InvalidateUserSessions(ctx context.Context, req *models.SessionUpdateRequest) error {
	userID := req.Session.UserID.Hex()

	log.WithFields(logrus.Fields{
		"user_id": userID,
		"service": req.ServiceName,
		"action":  req.Action,
	}).Info("Invalidating all user sessions")

	return m.repository.InvalidateUserSessions(ctx, req.Session.UserID)
}

func (m *manager) ValidateSessionWithCache(ctx context.Context, req *models.SessionUpdateRequest) (bool, error) {
	sessionID := req.Session.SessionID
	userID := req.Session.UserID
	cacheKey := fmt.Sprintf("session:%s:%s", userID.Hex(), sessionID)

	sessionData, err := m.cacheService.GetActiveSession(ctx, cacheKey)
	if err != nil && !errors.Is(err, models.ErrRedisGet) {
		log.WithError(err).Error("Failed to check Redis cache")
	}

	if sessionData != nil {
		log.WithField("session_id", sessionID).Debug("Session found in Redis cache")
		m.cacheService.UpdateSessionActivity(ctx, cacheKey)
		return true, nil
	}

	return m.validateSessionFromDB(ctx, req)
}

func (m *manager) validateSessionFromDB(ctx context.Context, req *models.SessionUpdateRequest) (bool, error) {
	session, err := m.repository.GetByID(ctx, req.Session.SessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) {
			return false, models.ErrSessionNotFound
		}
		return false, err
	}

	if !session.IsValidSession() {
		return false, models.ErrSessionExpired
	}

	req.Session = session
	m.UpdateActivity(req)
	m.cacheService.CacheActiveSession(ctx, session)
	m.repository.Update(ctx, session)

	return true, nil
}

func (m *manager) GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error) {
	return m.repository.GetActiveSessions(ctx, limit)
}

func (m *manager) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	return m.repository.GetByRefreshToken(ctx, refreshToken)
}

func (m *manager) UpdateSessionActivity(ctx context.Context, msg *models.ActivityMessage) error {
	session, err := m.repository.GetByID(ctx, msg.SessionID)
	if err != nil {
		return err
	}

	m.updateSessionFromMessage(session, msg)
	m.logActivityUpdate(session, msg)

	cacheKey := fmt.Sprintf("session:%s:%s", msg.UserID, msg.SessionID)
	m.cacheService.UpdateSessionActivity(ctx, cacheKey)

	return m.repository.Update(ctx, session)
}

func (m *manager) updateSessionFromMessage(session *models.Session, msg *models.ActivityMessage) {
	session.LastActiveAt = time.Now()
	session.LastService = msg.ServiceName

	session.AddAction(msg.Action)

	m.updateClientInfo(session, msg.UserAgent, msg.IPAddress)
}

func (m *manager) logActivityUpdate(session *models.Session, msg *models.ActivityMessage) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"session_id":  msg.SessionID,
		"user_id":     msg.UserID,
		"service":     msg.ServiceName,
		"action":      msg.Action,
		"ip_address":  session.IPAddress,
		"device_type": deviceType,
	}).Debug("Updated session activity")
}

// RefreshSessionDetails updates session with new client information during token refresh
func (m *manager) RefreshSessionDetails(ctx context.Context, req *models.SessionUpdateRequest) error {
	if req.Session == nil {
		return models.ErrSessionNotFound
	}

	req.Session.LastActiveAt = time.Now()
	req.Session.LastService = req.ServiceName
	req.Session.AddAction(req.Action)

	m.updateClientInfoAndLog(req)

	return m.repository.Update(ctx, req.Session)
}

func (m *manager) updateClientInfoAndLog(req *models.SessionUpdateRequest) {
	session := req.Session

	if req.IPAddress != "" && req.IPAddress != session.IPAddress {
		m.logIPChange(session.SessionID, session.IPAddress, req.IPAddress)
		session.IPAddress = req.IPAddress
	}

	if req.UserAgent != "" && req.UserAgent != session.UserAgent {
		m.logUserAgentChange(session.SessionID, session.UserAgent, req.UserAgent)
		session.UserAgent = req.UserAgent
		session.DeviceInfo = ParseDeviceInfo(req.UserAgent)
	}

	m.logSessionRefresh(session, req.ServiceName, req.Action)
}

func (m *manager) logIPChange(sessionID, oldIP, newIP string) {
	log.WithFields(logrus.Fields{
		"session_id": sessionID,
		"old_ip":     oldIP,
		"new_ip":     newIP,
	}).Info("IP address updated during session refresh")
}

func (m *manager) logUserAgentChange(sessionID, oldAgent, newAgent string) {
	log.WithFields(logrus.Fields{
		"session_id": sessionID,
		"old_agent":  oldAgent,
		"new_agent":  newAgent,
	}).Info("User agent updated during session refresh")
}

func (m *manager) logSessionRefresh(session *models.Session, serviceName, action string) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"session_id":  session.SessionID,
		"service":     serviceName,
		"action":      action,
		"ip_address":  session.IPAddress,
		"device_type": deviceType,
	}).Info("Refreshed session with updated details")
}

func (m *manager) generateSessionID() string {
	return "sess_" + uuid.New().String()
}

func (m *manager) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
