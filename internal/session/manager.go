package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var log = logrus.StandardLogger()

// Manager handles session operations and lifecycle
type Manager struct {
	repository Repository
}

// NewManager creates a new session manager with specified token expirations
func NewManager(db *clients.MongoDB, cfg *config.Configuration) *Manager {
	return &Manager{
		repository: NewSessionRepository(db, cfg.Database.SessionCollection),
	}
}

// CreateSession creates a new session for the specified user
func (m *Manager) CreateSession(ctx context.Context, userID primitive.ObjectID, userAgent, ipAddress string) (*models.Session, error) {
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

func (m *Manager) Update(ctx context.Context, session *models.Session) error {
	return m.repository.Update(ctx, session)
}

// ValidateSession validates session and returns status information
func (m *Manager) ValidateSession(session *models.Session) *models.SessionStatus {
	if session == nil {
		return &models.SessionStatus{
			IsValid:  false,
			IsActive: false,
		}
	}

	return session.ToSessionStatus()
}

// IsSessionValid checks if session is valid for authentication
func (m *Manager) IsSessionValid(session *models.Session) bool {
	if session == nil {
		return false
	}
	return session.IsValidSession()
}

// UpdateActivity updates session's last active timestamp
func (m *Manager) UpdateActivity(session *models.Session) {
	if session != nil {
		session.UpdateActivity()
	}
}

// InvalidateSession marks session as inactive and logged out
func (m *Manager) InvalidateSession(session *models.Session) {
	if session != nil {
		session.Logout()
	}
}

// IsRefreshTokenValid validates refresh token against session
func (m *Manager) IsRefreshTokenValid(session *models.Session, refreshToken string) bool {
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
func (m *Manager) GetSessionAge(session *models.Session) map[string]int64 {
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
func (m *Manager) GetTimeUntilExpiry(session *models.Session) time.Duration {
	if session == nil {
		return 0
	}
	return session.GetTimeUntilExpiry()
}

// generateSessionID creates a unique session identifier
func (m *Manager) generateSessionID() string {
	return "sess_" + uuid.New().String()
}

// generateRefreshToken creates a cryptographically secure refresh token
func (m *Manager) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (m *Manager) InvalidateUserSessions(ctx context.Context, userID string) error {
	id, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return err
	}
	return m.repository.InvalidateUserSessions(ctx, id)
}
