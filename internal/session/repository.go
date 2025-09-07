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
)

type repository struct {
	collection *mongo.Collection
}

type Repository interface {
	Create(ctx context.Context, session *models.Session) (*models.Session, error)
	GetByID(ctx context.Context, sessionID string) (*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
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
