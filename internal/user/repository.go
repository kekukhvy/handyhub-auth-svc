package user

import (
	"context"
	"errors"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

var log = logrus.StandardLogger()

type Repository interface {
	Create(ctx context.Context, user *models.User) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error)
	SaveVerificationToken(ctx context.Context, userID primitive.ObjectID, token string, expiresAt time.Time) error
}

type userRepository struct {
	collection *mongo.Collection
}

func NewUserRepository(db *clients.MongoDB, collectionName string) *userRepository {
	return &userRepository{
		collection: db.Database.Collection(collectionName),
	}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *models.User) (*models.User, error) {
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	result, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, models.ErrEmailAlreadyExists
		}

		log.WithError(err).Error("Failed to create user")
		return nil, models.ErrDatabaseInsert
	}

	user.ID = result.InsertedID.(primitive.ObjectID)
	log.WithField("user_id", user.ID.Hex()).Info("User created successfully")

	return user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	filter := bson.M{
		"email":      email,
		"deleted_at": bson.M{"$exists": false},
	}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, models.ErrUserNotFound
		}
		log.WithError(err).WithField("email", email).Error("Failed to get user by email")
		return nil, models.ErrDatabaseQuery
	}

	return &user, nil
}

func (r *userRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	var user models.User
	filter := bson.M{
		"_id":        id,
		"deleted_at": bson.M{"$exists": false},
	}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, models.ErrUserNotFound
		}
		log.WithError(err).WithField("user_id", id.Hex()).Error("Failed to get user by ID")
		return nil, models.ErrDatabaseQuery
	}

	return &user, nil
}

func (r *userRepository) SaveVerificationToken(ctx context.Context, userID primitive.ObjectID, token string, expiresAt time.Time) error {
	filter := bson.M{
		"_id":        userID,
		"deleted_at": bson.M{"$exists": false},
	}

	update := bson.M{
		"$set": bson.M{
			"verification_token":   token,
			"verification_expires": expiresAt,
			"updated_at":           time.Now(),
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	return err
}
