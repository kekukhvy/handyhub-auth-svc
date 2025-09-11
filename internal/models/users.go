package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
	ID                  primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	FirstName           string             `json:"firstName" bson:"first_name" validate:"required,min=2,max=50"`
	LastName            string             `json:"lastName" bson:"last_name" validate:"required,min=2,max=50"`
	Email               string             `json:"email" bson:"email" validate:"required,email"`
	Password            string             `json:"password,omitempty" bson:"password" validate:"required,min=6"`
	Phone               string             `json:"phone,omitempty" bson:"phone,omitempty"`
	Role                string             `json:"role" bson:"role" validate:"required,oneof=admin client executor moderator"`
	Status              string             `json:"status" bson:"status" validate:"required,oneof=active inactive suspended"`
	VerificationToken   *string            `json:"-" bson:"verification_token,omitempty"`
	VerificationExpires *time.Time         `json:"-" bson:"verification_expires,omitempty"`
	IsEmailVerified     bool               `json:"isEmailVerified" bson:"is_email_verified"`
	EmailVerifiedAt     *time.Time         `json:"emailVerifiedAt,omitempty" bson:"email_verified_at,omitempty"`
	RegistrationDate    time.Time          `json:"registrationDate" bson:"registration_date"`
	LastLoginAt         *time.Time         `json:"lastLoginAt,omitempty" bson:"last_login_at,omitempty"`
	LastActiveAt        *time.Time         `json:"lastActiveAt,omitempty" bson:"last_active_at,omitempty"`
	FailedLoginCount    int                `json:"failedLoginCount" bson:"failed_login_count"`
	LastFailedLoginAt   *time.Time         `json:"lastFailedLoginAt,omitempty" bson:"last_failed_login_at,omitempty"`
	Avatar              *string            `json:"avatar,omitempty" bson:"avatar,omitempty"`
	TimeZone            string             `json:"timeZone" bson:"time_zone"`
	Language            string             `json:"language" bson:"language"`
	CreatedAt           time.Time          `json:"createdAt" bson:"created_at"`
	UpdatedAt           time.Time          `json:"updatedAt" bson:"updated_at"`
	DeletedAt           *time.Time         `json:"deletedAt,omitempty" bson:"deleted_at,omitempty"`
}

// Role constants
const (
	RoleAdmin     = "admin"
	RoleClient    = "client"
	RoleExecutor  = "executor"
	RoleModerator = "moderator"
)

// Status constants
const (
	StatusActive    = "active"
	StatusInactive  = "inactive"
	StatusSuspended = "suspended"
)

// Default values
const (
	DefaultLanguage = "en"
	DefaultTimeZone = "UTC"
	DefaultRole     = RoleClient
	DefaultStatus   = StatusInactive
)

// Valid roles and statuses for validation
var (
	ValidRoles    = []string{RoleAdmin, RoleClient, RoleExecutor, RoleModerator}
	ValidStatuses = []string{StatusActive, StatusInactive, StatusSuspended}
)

// GetFullName returns user's full name
func (u *User) GetFullName() string {
	return u.FirstName + " " + u.LastName
}

// IsActive checks if user is active
func (u *User) IsActive() bool {
	return u.Status == StatusActive && u.DeletedAt == nil
}

// IsVerified checks if user email is verified
func (u *User) IsVerified() bool {
	return u.IsEmailVerified
}

// HasRole checks if user has specific role
func (u *User) HasRole(role string) bool {
	return u.Role == role
}

// IsAdmin checks if user is admin
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// SetDefaults sets default values for user
func (u *User) SetDefaults() {
	now := time.Now()

	if u.Role == "" {
		u.Role = DefaultRole
	}

	if u.Status == "" {
		u.Status = DefaultStatus
	}

	if u.Language == "" {
		u.Language = DefaultLanguage
	}

	if u.TimeZone == "" {
		u.TimeZone = DefaultTimeZone
	}

	if u.RegistrationDate.IsZero() {
		u.RegistrationDate = now
	}

	if u.CreatedAt.IsZero() {
		u.CreatedAt = now
	}

	u.UpdatedAt = now
}

// IsValidRole validates if role is valid
func (u *User) IsValidRole() bool {
	for _, validRole := range ValidRoles {
		if validRole == u.Role {
			return true
		}
	}
	return false
}

// IsValidStatus validates if status is valid
func (u *User) IsValidStatus() bool {
	for _, validStatus := range ValidStatuses {
		if validStatus == u.Status {
			return true
		}
	}
	return false
}

func (u *User) ToProfile() *UserProfile {
	return &UserProfile{
		ID:               u.ID,
		FirstName:        u.FirstName,
		LastName:         u.LastName,
		Email:            u.Email,
		Phone:            u.Phone,
		Role:             u.Role,
		Status:           u.Status,
		IsEmailVerified:  u.IsEmailVerified,
		RegistrationDate: u.RegistrationDate,
		LastLoginAt:      u.LastLoginAt,
		Avatar:           u.Avatar,
		TimeZone:         u.TimeZone,
		Language:         u.Language,
		CreatedAt:        u.CreatedAt,
		UpdatedAt:        u.UpdatedAt,
		LastActiveAt:     u.LastActiveAt,
	}
}

func (r *RegisterRequest) ToUser() *User {
	user := &User{
		FirstName: r.FirstName,
		LastName:  r.LastName,
		Email:     r.Email,
		Password:  r.Password,
		Phone:     r.Phone,
		Language:  r.Language,
		TimeZone:  r.TimeZone,
	}
	user.SetDefaults()
	return user
}
