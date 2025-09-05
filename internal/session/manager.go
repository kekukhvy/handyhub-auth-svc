package session

import (
	"crypto/rand"
	"encoding/hex"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Manager handles session operations and lifecycle
type Manager struct {
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
}

// NewManager creates a new session manager with specified token expirations
func NewManager(accessTokenExp, refreshTokenExp int) *Manager {
	return &Manager{
		accessTokenExpiration:  time.Duration(accessTokenExp) * time.Minute,
		refreshTokenExpiration: time.Duration(refreshTokenExp) * time.Minute,
	}
}

// CreateSession creates a new session for the specified user
func (m *Manager) CreateSession(userID primitive.ObjectID, userAgent, ipAddress string) (*models.Session, error) {
	now := time.Now()
	sessionID := m.generateSessionID()

	refreshToken, err := m.generateRefreshToken()
	if err != nil {
		return nil, models.ErrSessionCreating
	}

	session := &models.Session{
		SessionID:    sessionID,
		UserID:       userID,
		RefreshToken: refreshToken,
		UserAgent:    userAgent,
		IPAddress:    ipAddress,
		CreatedAt:    now,
		ExpiresAt:    now.Add(m.refreshTokenExpiration),
		LastActiveAt: now,
		IsActive:     true,
		DeviceInfo:   ParseDeviceInfo(userAgent),
	}

	return session, nil
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

// ShouldRefreshToken determines if access token should be refreshed
func (m *Manager) ShouldRefreshToken(tokenAge time.Duration) bool {
	// Refresh if token is more than 75% through its lifetime
	threshold := m.accessTokenExpiration * 3 / 4
	return tokenAge > threshold
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
