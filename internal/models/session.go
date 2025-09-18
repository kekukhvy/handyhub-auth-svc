package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Session represents user session
type Session struct {
	ID           primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	SessionID    string             `json:"sessionId" bson:"session_id"`
	UserID       primitive.ObjectID `json:"userId" bson:"user_id"`
	RefreshToken string             `json:"refreshToken" bson:"refresh_token"`
	AccessToken  string             `json:"accessToken,omitempty" bson:"access_token,omitempty"`
	UserAgent    string             `json:"userAgent,omitempty" bson:"user_agent,omitempty"`
	IPAddress    string             `json:"ipAddress,omitempty" bson:"ip_address,omitempty"`
	CreatedAt    time.Time          `json:"createdAt" bson:"created_at"`
	ExpiresAt    time.Time          `json:"expiresAt" bson:"expires_at"`
	LastActiveAt time.Time          `json:"lastActiveAt" bson:"last_active_at"`
	LastService  string             `json:"lastService,omitempty" bson:"last_service,omitempty"`
	LastAction   string             `json:"lastAction,omitempty" bson:"last_action,omitempty"`
	IsActive     bool               `json:"isActive" bson:"is_active"`
	LogoutAt     *time.Time         `json:"logoutAt,omitempty" bson:"logout_at,omitempty"`
	DeviceInfo   *DeviceInfo        `json:"deviceInfo,omitempty" bson:"device_info,omitempty"`
}

type SessionCreateRequest struct {
	UserID      primitive.ObjectID
	UserAgent   string
	IPAddress   string
	ServiceName string
	Action      string
}

type SessionUpdateRequest struct {
	Session     *Session
	ServiceName string
	Action      string
	UserAgent   string
	IPAddress   string
}

// DeviceInfo represents device information for session tracking
type DeviceInfo struct {
	DeviceType string `json:"deviceType" bson:"device_type"` // mobile, desktop, tablet
	OS         string `json:"os" bson:"os"`                  // iOS, Android, Windows, macOS, Linux
	Browser    string `json:"browser" bson:"browser"`        // Chrome, Firefox, Safari, etc.
	Version    string `json:"version" bson:"version"`        // Browser/OS version
}

// SessionStatus represents session status for validation
type SessionStatus struct {
	IsValid      bool      `json:"isValid"`
	IsActive     bool      `json:"isActive"`
	ExpiresAt    time.Time `json:"expiresAt"`
	LastActiveAt time.Time `json:"lastActiveAt"`
	SessionAge   int64     `json:"sessionAge"` // in seconds
}

// ActiveSession represents session data stored in Redis
type ActiveSession struct {
	SessionID    string             `json:"sessionId"`
	UserID       primitive.ObjectID `json:"userId"`
	CreatedAt    time.Time          `json:"createdAt"`
	ExpiresAt    time.Time          `json:"expiresAt"`
	LastActiveAt time.Time          `json:"lastActiveAt"`
	IPAddress    string             `json:"ipAddress,omitempty"`
	UserAgent    string             `json:"userAgent,omitempty"`
}

// Session constants
const (
	SessionStatusActive    = "active"
	SessionStatusExpired   = "expired"
	SessionStatusLoggedOut = "logged_out"
	SessionStatusInvalid   = "invalid"
)

// Device type constants
const (
	DeviceTypeMobile  = "mobile"
	DeviceTypeDesktop = "desktop"
	DeviceTypeTablet  = "tablet"
	DeviceTypeUnknown = "unknown"
)

// IsExpired checks if session is expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsValidSession checks if session is valid and active
func (s *Session) IsValidSession() bool {
	return s.IsActive && !s.IsExpired() && s.LogoutAt == nil
}

// GetAge returns session age in seconds
func (s *Session) GetAge() int64 {
	return int64(time.Since(s.CreatedAt).Seconds())
}

// GetTimeUntilExpiry returns time until session expires
func (s *Session) GetTimeUntilExpiry() time.Duration {
	if s.IsExpired() {
		return 0
	}
	return time.Until(s.ExpiresAt)
}

// UpdateActivity updates last active timestamp
func (s *Session) UpdateActivity() {
	s.LastActiveAt = time.Now()
}

// Logout marks session as logged out
func (s *Session) Logout() {
	now := time.Now()
	s.LogoutAt = &now
	s.IsActive = false
}

// GetStatus returns current session status
func (s *Session) GetStatus() string {
	if s.LogoutAt != nil {
		return SessionStatusLoggedOut
	}
	if !s.IsActive {
		return SessionStatusInvalid
	}
	if s.IsExpired() {
		return SessionStatusExpired
	}
	return SessionStatusActive
}

type ActivityMessage struct {
	UserID      string            `json:"user_id"`
	SessionID   string            `json:"session_id"`
	ServiceName string            `json:"service_name"`
	Action      string            `json:"action"`
	IPAddress   string            `json:"ip_address,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Timestamp   time.Time         `json:"timestamp"`
}

// ToActiveSession converts Session to ActiveSession for Redis storage
func (s *Session) ToActiveSession() *ActiveSession {
	return &ActiveSession{
		SessionID:    s.SessionID,
		UserID:       s.UserID,
		CreatedAt:    s.CreatedAt,
		ExpiresAt:    s.ExpiresAt,
		LastActiveAt: s.LastActiveAt,
		IPAddress:    s.IPAddress,
		UserAgent:    s.UserAgent,
	}
}

// ToSessionStatus converts Session to SessionStatus for validation
func (s *Session) ToSessionStatus() *SessionStatus {
	return &SessionStatus{
		IsValid:      s.IsValidSession(),
		IsActive:     s.IsActive,
		ExpiresAt:    s.ExpiresAt,
		LastActiveAt: s.LastActiveAt,
		SessionAge:   s.GetAge(),
	}
}
