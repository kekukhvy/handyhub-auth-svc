package user

import (
	"context"
	"errors"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/email"
	"handyhub-auth-svc/internal/models"
	"handyhub-auth-svc/internal/utils"
	"handyhub-auth-svc/internal/validators"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Service interface {
	CreateUser(ctx context.Context, user *models.User) (*models.User, error)
	ValidateUser(user *models.User) error
	IsEmailUnique(ctx context.Context, email string, excludeUserID *primitive.ObjectID) (bool, error)
	SendVerificationEmail(ctx context.Context, userID primitive.ObjectID) error
}

type userService struct {
	userRepo Repository
	emailSvc email.Service
	cfg      *config.CacheConfig
}

func NewUserService(
	userRepo Repository,
	emailService email.Service,
	cfg *config.CacheConfig) Service {
	return &userService{
		userRepo: userRepo,
		emailSvc: emailService,
		cfg:      cfg,
	}
}

func (s *userService) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := s.ValidateUser(user); err != nil {
		return nil, err
	}

	user.SetDefaults()

	createdUser, err := s.userRepo.Create(ctx, user)
	if err != nil {
		log.WithError(err).WithField("email", user.Email).Error("Failed to create user")
		return nil, err
	}

	log.WithField("user_id", createdUser.ID.Hex()).
		WithField("email", createdUser.Email).
		Info("User created successfully")

	return createdUser, nil
}

func (s *userService) ValidateUser(user *models.User) error {
	if user == nil {
		return models.ErrInvalidParams
	}

	// Validate required fields
	if strings.TrimSpace(user.FirstName) == "" {
		return models.ErrInvalidParams
	}

	if strings.TrimSpace(user.LastName) == "" {
		return models.ErrInvalidParams
	}

	if strings.TrimSpace(user.Email) == "" {
		return models.ErrInvalidParams
	}

	// Validate email format using validator
	emailValidator := validators.NewEmailValidator()
	if err := emailValidator.Validate(user.Email); err != nil {
		return models.ErrInvalidEmail
	}

	// Validate role
	if user.Role != "" && !user.IsValidRole() {
		return models.ErrInvalidRole
	}

	// Validate status
	if user.Status != "" && !user.IsValidStatus() {
		return models.ErrInvalidStatus
	}

	return nil
}

func (s *userService) IsEmailUnique(ctx context.Context, email string, excludeUserID *primitive.ObjectID) (bool, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return true, nil // Email is unique
		}
		return false, err // Database error
	}

	// If we found a user with this email, check if it's the same user we're excluding
	if excludeUserID != nil && user.ID == *excludeUserID {
		return true, nil // Same user, so email is "unique" for update purposes
	}

	return false, nil // Email is not unique
}

func (s *userService) SendVerificationEmail(ctx context.Context, userID primitive.ObjectID) error {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	token, err := utils.GenerateSecureToken(32)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(24 * time.Hour)
	err = s.userRepo.SaveVerificationToken(ctx, userID, token, expiresAt)
	if err != nil {
		return err
	}

	return s.emailSvc.SendVerificationEmail(user.Email, user.FirstName, token)
}
