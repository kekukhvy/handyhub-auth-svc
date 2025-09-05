package session

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Filters provides MongoDB query filters for session operations
type Filters struct{}

// NewFilters creates a new filters instance
func NewFilters() *Filters {
	return &Filters{}
}

// ActiveSessions returns filter for finding active sessions for a user
func (f *Filters) ActiveSessions(userID primitive.ObjectID) map[string]interface{} {
	return map[string]interface{}{
		"user_id":    userID,
		"is_active":  true,
		"expires_at": map[string]interface{}{"$gt": time.Now()},
		"logout_at":  nil,
	}
}

// ExpiredSessions returns filter for finding expired sessions
func (f *Filters) ExpiredSessions() map[string]interface{} {
	return map[string]interface{}{
		"$or": []map[string]interface{}{
			{"expires_at": map[string]interface{}{"$lt": time.Now()}},
			{"is_active": false},
			{"logout_at": map[string]interface{}{"$ne": nil}},
		},
	}
}

// SessionByID returns filter for finding session by session ID
func (f *Filters) SessionByID(sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"session_id": sessionID,
	}
}

// SessionByRefreshToken returns filter for finding session by refresh token
func (f *Filters) SessionByRefreshToken(refreshToken string) map[string]interface{} {
	return map[string]interface{}{
		"refresh_token": refreshToken,
		"is_active":     true,
		"expires_at":    map[string]interface{}{"$gt": time.Now()},
		"logout_at":     nil,
	}
}

// UserSessions returns filter for finding all sessions for a user
func (f *Filters) UserSessions(userID primitive.ObjectID) map[string]interface{} {
	return map[string]interface{}{
		"user_id": userID,
	}
}

// RecentUserSessions returns filter for finding recent sessions for a user
func (f *Filters) RecentUserSessions(userID primitive.ObjectID, days int) map[string]interface{} {
	since := time.Now().AddDate(0, 0, -days)
	return map[string]interface{}{
		"user_id":    userID,
		"created_at": map[string]interface{}{"$gte": since},
	}
}

// SessionsByIPAddress returns filter for finding sessions from specific IP
func (f *Filters) SessionsByIPAddress(ipAddress string) map[string]interface{} {
	return map[string]interface{}{
		"ip_address": ipAddress,
	}
}

// SessionsByDevice returns filter for finding sessions from specific device type
func (f *Filters) SessionsByDevice(userID primitive.ObjectID, deviceType string) map[string]interface{} {
	return map[string]interface{}{
		"user_id":                 userID,
		"device_info.device_type": deviceType,
	}
}

// SuspiciousSessions returns filter for finding potentially suspicious sessions
func (f *Filters) SuspiciousSessions(userID primitive.ObjectID, hours int) map[string]interface{} {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	return map[string]interface{}{
		"user_id":    userID,
		"created_at": map[string]interface{}{"$gte": since},
		"is_active":  true,
	}
}

// ActiveSessionsCount returns aggregation pipeline for counting active sessions
func (f *Filters) ActiveSessionsCount(userID primitive.ObjectID) []map[string]interface{} {
	return []map[string]interface{}{
		{
			"$match": f.ActiveSessions(userID),
		},
		{
			"$count": "active_sessions",
		},
	}
}

// SessionsByTimeRange returns filter for sessions within time range
func (f *Filters) SessionsByTimeRange(userID primitive.ObjectID, from, to time.Time) map[string]interface{} {
	return map[string]interface{}{
		"user_id": userID,
		"created_at": map[string]interface{}{
			"$gte": from,
			"$lte": to,
		},
	}
}

// UpdateActiveSession returns update operation for updating session activity
func (f *Filters) UpdateActiveSession() map[string]interface{} {
	return map[string]interface{}{
		"$set": map[string]interface{}{
			"last_active_at": time.Now(),
		},
	}
}

// UpdateLogoutSession returns update operation for session logout
func (f *Filters) UpdateLogoutSession() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"$set": map[string]interface{}{
			"logout_at": &now,
			"is_active": false,
		},
	}
}

// InvalidateUserSessions returns update operation for invalidating all user sessions
func (f *Filters) InvalidateUserSessions() map[string]interface{} {
	now := time.Now()
	return map[string]interface{}{
		"$set": map[string]interface{}{
			"logout_at": &now,
			"is_active": false,
		},
	}
}
