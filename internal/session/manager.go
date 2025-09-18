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

// Manager handles session operations and lifecycle
type manager struct {
	repository   Repository
	cacheService cache.Service
}

type Manager interface {
	CreateSession(ctx context.Context, userID primitive.ObjectID, userAgent, ipAddress string) (*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
	ValidateSession(session *models.Session) *models.SessionStatus
	GetByID(ctx context.Context, sessionID string) (*models.Session, error)
	IsSessionValid(session *models.Session) bool
	UpdateActivity(session *models.Session)
	InvalidateSession(ctx context.Context, session *models.Session)
	IsRefreshTokenValid(session *models.Session, refreshToken string) bool
	GetSessionAge(session *models.Session) map[string]int64
	GetTimeUntilExpiry(session *models.Session) time.Duration
	InvalidateUserSessions(ctx context.Context, userID string) error
	ValidateSessionWithCache(ctx context.Context, sessionID string, userID primitive.ObjectID) (bool, error)
	GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error)
	GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	UpdateSessionActivity(ctx context.Context, msg *models.ActivityMessage) error
}

// NewManager creates a new session manager with specified token expirations
func NewManager(db *clients.MongoDB, cfg *config.Configuration, cacheService cache.Service) Manager {
	return &manager{
		repository:   NewSessionRepository(db, cfg.Database.SessionCollection),
		cacheService: cacheService,
	}
}

// CreateSession creates a new session for the specified user
func (m *manager) CreateSession(ctx context.Context, userID primitive.ObjectID, userAgent, ipAddress string) (*models.Session, error) {
	now := time.Now()
	sessionID := m.generateSessionID()

	session := &models.Session{
		SessionID:    sessionID,
		UserID:       userID,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		CreatedAt:    now,
		LastActiveAt: now,
		IsActive:     true,
		DeviceInfo:   ParseDeviceInfo(userAgent),
	}

	session, err := m.repository.Create(ctx, session)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func (m *manager) Update(ctx context.Context, session *models.Session) error {
	return m.repository.Update(ctx, session)
}

// ValidateSession validates session and returns status information
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

// IsSessionValid checks if session is valid for authentication
func (m *manager) IsSessionValid(session *models.Session) bool {
	if session == nil {
		return false
	}
	return session.IsValidSession()
}

// UpdateActivity updates session's last active timestamp
func (m *manager) UpdateActivity(session *models.Session) {
	if session != nil {
		session.UpdateActivity()
	}
}

// InvalidateSession marks session as inactive and logged out
func (m *manager) InvalidateSession(ctx context.Context, session *models.Session) {
	if session != nil {
		session.Logout()
	}
	m.repository.Update(ctx, session)
}

// IsRefreshTokenValid validates refresh token against session
func (m *manager) IsRefreshTokenValid(session *models.Session, refreshToken string) bool {
	if session == nil {
		return false
	}

	// Check if session is valid
	if !session.IsValidSession() {
		return false
	}

	// Check if refresh token matches
	return session.RefreshToken == refreshToken
}

// GetSessionAge returns session age in various time units
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

// GetTimeUntilExpiry returns time remaining until session expires
func (m *manager) GetTimeUntilExpiry(session *models.Session) time.Duration {
	if session == nil {
		return 0
	}
	return session.GetTimeUntilExpiry()
}

// generateSessionID creates a unique session identifier
func (m *manager) generateSessionID() string {
	return "sess_" + uuid.New().String()
}

// generateRefreshToken creates a cryptographically secure refresh token
func (m *manager) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (m *manager) InvalidateUserSessions(ctx context.Context, userID string) error {
	id, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}
	return m.repository.InvalidateUserSessions(ctx, id)
}

func (m *manager) ValidateSessionWithCache(ctx context.Context, sessionID string, userID primitive.ObjectID) (bool, error) {
	log.WithField("session_id", sessionID).Debug("Validating session with cache")

	// Check Redis cache first
	cacheKey := fmt.Sprintf("session:%s:%s", userID.Hex(), sessionID)

	// Try to get session from Redis
	sessionData, err := m.cacheService.GetActiveSession(ctx, cacheKey)
	if err != nil && !errors.Is(err, models.ErrRedisGet) {
		log.WithError(err).Error("Failed to check Redis cache")
		// Continue to MongoDB check on Redis errors
	}

	// If found in Redis and valid
	if sessionData != nil {
		log.WithField("session_id", sessionID).Debug("Session found in Redis cache")

		// Update activity in cache
		if err := m.cacheService.UpdateSessionActivity(ctx, cacheKey); err != nil {
			log.WithError(err).Warn("Failed to update session activity in cache")
		}

		return true, nil
	}

	log.WithField("session_id", sessionID).Debug("Session not found in Redis, checking MongoDB")

	// Fallback to MongoDB
	session, err := m.repository.GetByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, models.ErrSessionNotFound) {
			return false, models.ErrSessionNotFound
		}
		log.WithError(err).Error("Failed to get session from MongoDB")
		return false, err
	}

	//Check if session is valid
	if !session.IsValidSession() {
		log.WithField("session_id", sessionID).Warn("Session found but invalid")
		return false, models.ErrSessionExpired
	}

	//Session is valid - restore to Redis and update activity
	session.UpdateActivity()

	// Cache the session back to Redis
	if err := m.cacheService.CacheActiveSession(ctx, session); err != nil {
		log.WithError(err).Warn("Failed to restore session to cache")
		// Don't fail the request if caching fails
	}

	// Update activity in MongoDB
	if err := m.repository.Update(ctx, session); err != nil {
		log.WithError(err).Error("Failed to update session activity in MongoDB")
		// Don't fail the request if activity update fails
	}

	log.WithField("session_id", sessionID).Debug("Session validated and restored to cache")
	return true, nil
}

func (m *manager) GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error) {
	return m.repository.GetActiveSessions(ctx, limit)
}

func (m *manager) GetSessionByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	return m.repository.GetByRefreshToken(ctx, refreshToken)
}

func (m *manager) UpdateSessionActivity(ctx context.Context, msg *models.ActivityMessage) error {
	// Get current session
	session, err := m.repository.GetByID(ctx, msg.SessionID)
	if err != nil {
		return err
	}

	// Update activity fields
	session.LastActiveAt = time.Now()
	session.LastService = msg.ServiceName
	session.LastAction = msg.Action

	// Update IP and UserAgent if provided
	if msg.IPAddress != "" {
		session.IPAddress = msg.IPAddress
	}
	if msg.UserAgent != "" {
		session.UserAgent = msg.UserAgent
	}

	if err := m.cacheService.UpdateSessionActivity(ctx, msg.SessionID); err != nil {
		log.WithError(err).WithField("session_id", msg.SessionID).Warn("Failed to update cached session activity")
		// Not critical, continue
	}

	// Save to database
	return m.repository.Update(ctx, session)
}
