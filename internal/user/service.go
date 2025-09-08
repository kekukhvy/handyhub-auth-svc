package user

import (
	"context"
	"errors"
	"handyhub-auth-svc/internal/cache"
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
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	IncrementFailedLogin(ctx context.Context, userID primitive.ObjectID) error
	UpdateLastLogin(ctx context.Context, userID primitive.ObjectID) error
	GetUserByVerificationToken(ctx context.Context, token string) (*models.User, error)
	VerifyUserEmail(ctx context.Context, userID primitive.ObjectID) error
}

type userService struct {
	userRepo     Repository
	emailSvc     email.Service
	cacheService cache.Service
	cfg          *config.CacheConfig
}

func (s *userService) UpdateLastLogin(ctx context.Context, userID primitive.ObjectID) error {
	return s.userRepo.UpdateLastLogin(ctx, userID)
}

func (s *userService) IncrementFailedLogin(ctx context.Context, userID primitive.ObjectID) error {
	return s.userRepo.IncrementFailedLogin(ctx, userID)
}

func NewUserService(
	userRepo Repository,
	emailService email.Service,
	cfg *config.CacheConfig,
	cacheService cache.Service) Service {
	return &userService{
		userRepo:     userRepo,
		emailSvc:     emailService,
		cfg:          cfg,
		cacheService: cacheService,
	}
}

func (s *userService) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {

	log.WithField("email", user.Email).Debug("CreateUser")

	if err := s.ValidateUser(user); err != nil {
		return nil, err
	}

	user.SetDefaults()

	createdUser, err := s.userRepo.Create(ctx, user)
	if err != nil {
		log.WithError(err).WithField("email", user.Email).Error("Failed to create user")
		return nil, err
	}

	log.WithField("email", createdUser.Email).Debug("User created successfully")
	return createdUser, nil
}

func (s *userService) ValidateUser(user *models.User) error {
	log.WithField("email", user.Email).Debug("Validating user")
	if user == nil {
		return models.ErrInvalidValue
	}

	// Validate required fields
	if strings.TrimSpace(user.FirstName) == "" {
		return models.ErrInvalidValue
	}

	if strings.TrimSpace(user.LastName) == "" {
		return models.ErrInvalidValue
	}

	if strings.TrimSpace(user.Email) == "" {
		return models.ErrInvalidValue
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

	log.WithField("email", user.Email).Debug("User validated successfully")
	return nil
}

func (s *userService) IsEmailUnique(ctx context.Context, email string, excludeUserID *primitive.ObjectID) (bool, error) {
	log.WithField("email", email).Debug("Checking if email is unique")
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
			return true, nil // Email is unique
		}
		return false, err // Database error
	}

	// If we found a user with this email, check if it's the same user we're excluding
	if excludeUserID != nil && user.ID == *excludeUserID {
		log.WithField("email", email).Debug("Email belongs to the same user, considered unique for update")
		return true, nil // Same user, so email is "unique" for update purposes
	}

	return false, nil // Email is not unique
}

func (s *userService) SendVerificationEmail(ctx context.Context, userID primitive.ObjectID) error {

	user, err := s.userRepo.GetByID(ctx, userID)
	log.WithField("email", user.Email).Info("Sending verification email")
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

	log.WithField("user_id", userID.Hex()).Info("Verification email sent successfully")
	return s.emailSvc.SendVerificationEmail(user.Email, user.FirstName, token)
}

func (s *userService) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user, err := s.userRepo.GetByEmail(ctx, email)
	if err != nil {
		log.WithError(err).WithField("email", email).Error("Failed to get user by email")
		return nil, err
	}

	// Cache user profile
	s.cacheService.CacheUser(ctx, user, 30) // Shorter cache for email lookups

	return user, nil
}

func (s *userService) GetUserByVerificationToken(ctx context.Context, token string) (*models.User, error) {
	log.WithField("token_prefix", token[:min(10, len(token))]+"...").Debug("Getting user by verification token")

	user, err := s.userRepo.GetByVerificationToken(ctx, token)
	if err != nil {
		log.WithError(err).Error("Failed to get user by verification token")
		return nil, err
	}

	log.WithField("user_id", user.ID.Hex()).WithField("email", user.Email).Debug("User found by verification token")
	return user, nil
}

func (s *userService) VerifyUserEmail(ctx context.Context, userID primitive.ObjectID) error {
	log.WithField("user_id", userID.Hex()).Info("Verifying user email")

	err := s.userRepo.VerifyEmail(ctx, userID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.Hex()).Error("Failed to verify user email")
		return err
	}

	log.WithField("user_id", userID.Hex()).Info("User email verified successfully")
	return nil
}
