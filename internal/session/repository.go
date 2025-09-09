package session

import (
	"context"
	"errors"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/models"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type repository struct {
	collection *mongo.Collection
}

type Repository interface {
	Create(ctx context.Context, session *models.Session) (*models.Session, error)
	GetByID(ctx context.Context, sessionID string) (*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
	InvalidateUserSessions(ctx context.Context, userID primitive.ObjectID) error
	GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error)
	GetByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error)
	UpdateActivity(ctx context.Context, sessionID string) error
}

func NewSessionRepository(db *clients.MongoDB, collectionName string) Repository {
	collection := db.Database.Collection(collectionName)
	return &repository{collection: collection}
}

// Create creates a new session
func (r *repository) Create(ctx context.Context, session *models.Session) (*models.Session, error) {
	now := time.Now()
	session.CreatedAt = now
	session.LastActiveAt = now

	result, err := r.collection.InsertOne(ctx, session)
	if err != nil {
		log.WithError(err).Error("Failed to create session")
		return nil, models.ErrSessionCreating
	}

	session.ID = result.InsertedID.(primitive.ObjectID)
	log.WithField("session_id", session.SessionID).Info("Session created successfully")
	return session, nil
}

// GetByID retrieves session by session ID
func (r *repository) GetByID(ctx context.Context, sessionID string) (*models.Session, error) {
	var session models.Session
	filter := bson.M{"session_id": sessionID}

	err := r.collection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, models.ErrSessionNotFound
		}
		log.WithError(err).WithField("session_id", sessionID).Error("Failed to get session")
		return nil, models.ErrDatabaseQuery
	}

	return &session, nil
}

func (r *repository) Update(ctx context.Context, session *models.Session) error {
	filter := bson.M{"session_id": session.SessionID}
	update := bson.M{"$set": session}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("session_id", session.SessionID).Error("Failed to update session")
		return models.ErrSessionUpdating
	}

	if result.MatchedCount == 0 {
		return models.ErrSessionNotFound
	}

	return nil
}

func (r *repository) InvalidateUserSessions(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now()
	filter := bson.M{
		"user_id":   userID,
		"is_active": true,
		"logout_at": nil,
	}

	update := bson.M{
		"$set": bson.M{
			"is_active": false,
			"logout_at": &now,
		},
	}

	result, err := r.collection.UpdateMany(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to invalidate user sessions")
		return models.ErrSessionUpdating
	}

	log.WithField("user_id", userID.Hex()).
		WithField("sessions_invalidated", result.ModifiedCount).
		Info("User sessions invalidated")

	return nil
}

func (r *repository) GetActiveSessions(ctx context.Context, limit int) ([]*models.Session, error) {
	log.Debug("Getting active sessions for cleanup")

	filter := bson.M{
		"is_active": true,
		"logout_at": nil, // Only sessions that haven't been explicitly logged out
	}

	limitInt64 := int64(limit)
	options := options.FindOptions{
		Limit: &limitInt64,
		Sort:  bson.D{{"last_active_at", 1}}, // Сначала самые старые по активности
	}

	cursor, err := r.collection.Find(ctx, filter, &options)
	if err != nil {
		log.WithError(err).Error("Failed to find active sessions")
		return nil, models.ErrDatabaseQuery
	}
	defer cursor.Close(ctx)

	var sessions []*models.Session
	for cursor.Next(ctx) && len(sessions) < limit {
		var session models.Session
		if err := cursor.Decode(&session); err != nil {
			log.WithError(err).Error("Failed to decode session")
			continue
		}
		sessions = append(sessions, &session)
	}

	if err := cursor.Err(); err != nil {
		log.WithError(err).Error("Cursor error while reading sessions")
		return nil, models.ErrDatabaseQuery
	}

	log.WithField("count", len(sessions)).Debug("Retrieved active sessions for cleanup")
	return sessions, nil
}

func (r *repository) GetByRefreshToken(ctx context.Context, refreshToken string) (*models.Session, error) {
	log.WithField("refresh_token", refreshToken).Debug("Getting session by refresh token")
	var session models.Session
	filter := bson.M{
		"refresh_token": refreshToken,
		"is_active":     true,
		"expires_at":    bson.M{"$gt": time.Now()},
		"logout_at":     nil,
	}

	err := r.collection.FindOne(ctx, filter).Decode(&session)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, models.ErrSessionNotFound
		}
		log.WithError(err).Error("Failed to get session by refresh token %s", refreshToken)
		return nil, models.ErrDatabaseQuery
	}

	log.WithField("session_id", session.SessionID).Debug("Session retrieved by refresh token")
	return &session, nil
}

func (r *repository) UpdateActivity(ctx context.Context, sessionID string) error {
	filter := bson.M{
		"session_id": sessionID,
		"is_active":  true,
	}

	update := bson.M{
		"$set": bson.M{
			"last_active_at": time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("session_id", sessionID).Error("Failed to update session activity")
		return models.ErrSessionUpdating
	}

	return nil
}
