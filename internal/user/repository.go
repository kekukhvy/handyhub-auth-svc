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
	IncrementFailedLogin(ctx context.Context, userID primitive.ObjectID) error
	UpdateLastLogin(ctx context.Context, userID primitive.ObjectID) error
	GetByVerificationToken(ctx context.Context, token string) (*models.User, error)
	VerifyEmail(ctx context.Context, userID primitive.ObjectID) error
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

	log.WithFields(logrus.Fields{"email": user.Email}).Debug("Creating new user in db")

	result, err := r.collection.InsertOne(ctx, user)
	if err != nil {
		if mongo.IsDuplicateKeyError(err) {
			return nil, models.ErrEmailAlreadyExists
		}

		log.WithError(err).Error("Failed to create user")
		return nil, models.ErrDatabaseInsert
	}

	user.ID = result.InsertedID.(primitive.ObjectID)

	log.WithField("email", user.Email).Info("User created in db successfully ", user.ID.Hex())

	return user, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	log.WithField("email", email).Debug("Fetching user by email from db")

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

	log.WithField("email", email).Debug("User fetched by email from db successfully")
	return &user, nil
}

func (r *userRepository) GetByID(ctx context.Context, id primitive.ObjectID) (*models.User, error) {
	var user models.User
	log.WithField("user_id", id.Hex()).Debug("Fetching user by ID from db")
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

	log.WithField("email", user.Email).Debug("User fetched by ID from db successfully")
	return &user, nil
}

func (r *userRepository) SaveVerificationToken(ctx context.Context, userID primitive.ObjectID, token string, expiresAt time.Time) error {
	log.WithField("user_id", userID.Hex()).Debug("Saving verification token to db")
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
	log.WithField("user_id", userID.Hex()).Debug("Verification token saved to db successfully")
	return err
}

func (r *userRepository) IncrementFailedLogin(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now()
	filter := bson.M{
		"_id":        userID,
		"deleted_at": bson.M{"$exists": false},
	}

	update := bson.M{
		"$inc": bson.M{"failed_login_count": 1},
		"$set": bson.M{
			"last_failed_login_at": &now,
			"updated_at":           now,
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to increment failed login")
		return models.ErrDatabaseUpdate
	}

	return nil
}

func (r *userRepository) UpdateLastLogin(ctx context.Context, userID primitive.ObjectID) error {
	now := time.Now()
	filter := bson.M{
		"_id":        userID,
		"deleted_at": bson.M{"$exists": false},
	}

	update := bson.M{
		"$set": bson.M{
			"last_login_at":        &now,
			"last_active_at":       &now,
			"failed_login_count":   0,
			"last_failed_login_at": nil,
			"updated_at":           now,
		},
	}

	_, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to update last login")
		return models.ErrDatabaseUpdate
	}

	return nil
}

func (r *userRepository) GetByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	log.WithField("token_prefix", token[:min(10, len(token))]+"...").Debug("Fetching user by verification token from db")

	var user models.User
	filter := bson.M{
		"verification_token": token,
		"deleted_at":         bson.M{"$exists": false},
	}

	err := r.collection.FindOne(ctx, filter).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			log.Debug("User not found by verification token")
			return nil, models.ErrUserNotFound
		}
		log.WithError(err).Error("Failed to get user by verification token")
		return nil, models.ErrDatabaseQuery
	}

	log.WithField("email", user.Email).Debug("User fetched by verification token from db successfully")
	return &user, nil
}

func (r *userRepository) VerifyEmail(ctx context.Context, userID primitive.ObjectID) error {
	log.WithField("user_id", userID.Hex()).Debug("Verifying email in database")

	now := time.Now()
	filter := bson.M{
		"_id":        userID,
		"deleted_at": bson.M{"$exists": false},
	}

	update := bson.M{
		"$set": bson.M{
			"is_email_verified": true,
			"email_verified_at": &now,
			"status":            models.StatusActive, // Activate user after email verification
			"updated_at":        now,
		},
		"$unset": bson.M{
			"verification_token":   "",
			"verification_expires": "",
		},
	}

	result, err := r.collection.UpdateOne(ctx, filter, update)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to verify email in database")
		return models.ErrDatabaseUpdate
	}

	if result.MatchedCount == 0 {
		log.WithField("user_id", userID.Hex()).Error("User not found for email verification")
		return models.ErrUserNotFound
	}

	log.WithField("user_id", userID.Hex()).Info("Email verified in database successfully")
	return nil
}
