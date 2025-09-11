package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// LoginRequest represents user login request
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
}

// RegisterRequest represents user registration request
type RegisterRequest struct {
	FirstName string `json:"firstName" validate:"required,min=2,max=50"`
	LastName  string `json:"lastName" validate:"required,min=2,max=50"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required,min=6"`
	Phone     string `json:"phone,omitempty"`
	Language  string `json:"language,omitempty"`
	TimeZone  string `json:"timeZone,omitempty"`
}

// RefreshTokenRequest represents token refresh request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken" validate:"required"`
}

// ChangePasswordRequest represents password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword" validate:"required"`
	NewPassword     string `json:"newPassword" validate:"required,min=6"`
}

// ResetPasswordRequest represents password reset request
type ResetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordConfirmRequest represents password reset confirmation
type ResetPasswordConfirmRequest struct {
	Token       string `json:"token" validate:"required"`
	NewPassword string `json:"newPassword" validate:"required,min=6"`
}

// VerifyTokenRequest represents token verification request
type VerifyTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// UserProfile represents public user profile (without sensitive data)
type UserProfile struct {
	ID               primitive.ObjectID `json:"id"`
	FirstName        string             `json:"firstName"`
	LastName         string             `json:"lastName"`
	Email            string             `json:"email"`
	Phone            string             `json:"phone,omitempty"`
	Role             string             `json:"role"`
	Status           string             `json:"status"`
	IsEmailVerified  bool               `json:"isEmailVerified"`
	RegistrationDate time.Time          `json:"registrationDate"`
	LastLoginAt      *time.Time         `json:"lastLoginAt,omitempty"`
	Avatar           *string            `json:"avatar,omitempty"`
	TimeZone         string             `json:"timeZone"`
	Language         string             `json:"language"`
	CreatedAt        time.Time          `json:"createdAt"`
	UpdatedAt        time.Time          `json:"updatedAt"`
	LastActiveAt     *time.Time         `json:"lastActiveAt,omitempty"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	AccessToken           string       `json:"accessToken"`
	RefreshToken          string       `json:"refreshToken"`
	AccessTokenExpiresAt  time.Time    `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt time.Time    `json:"refreshTokenExpiresAt"`
	User                  *UserProfile `json:"user"`
	SessionID             string       `json:"sessionId"`
}

// RefreshTokenResponse represents token refresh response
type RefreshTokenResponse struct {
	AccessToken          string    `json:"accessToken"`
	AccessTokenExpiresAt time.Time `json:"accessTokenExpiresAt"`
}

// VerifyTokenResponse represents token verification response
type VerifyTokenResponse struct {
	Valid     bool               `json:"valid"`
	UserID    primitive.ObjectID `json:"userId,omitempty"`
	SessionID string             `json:"sessionId,omitempty"`
	ExpiresAt time.Time          `json:"expiresAt,omitempty"`
	IssuedAt  time.Time          `json:"issuedAt,omitempty"`
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID    primitive.ObjectID `json:"userId"`
	SessionID string             `json:"sessionId"`
	Email     string             `json:"email"`
	Role      string             `json:"role"`
	TokenType string             `json:"tokenType"` // access, refresh, reset
	IssuedAt  time.Time          `json:"issuedAt"`
	ExpiresAt time.Time          `json:"expiresAt"`
}

// PasswordResetToken represents password reset token
type PasswordResetToken struct {
	ID        primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID    primitive.ObjectID `json:"userId" bson:"user_id"`
	Token     string             `json:"token" bson:"token"`
	ExpiresAt time.Time          `json:"expiresAt" bson:"expires_at"`
	Used      bool               `json:"used" bson:"used"`
	CreatedAt time.Time          `json:"createdAt" bson:"created_at"`
	UsedAt    *time.Time         `json:"usedAt,omitempty" bson:"used_at,omitempty"`
}

// Token type constants
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
	TokenTypeReset   = "reset"
)

// Response status constants
const (
	StatusSuccess = "success"
	StatusError   = "error"
)

// Common response messages
const (
	MessageLoginSuccess          = "Login successful"
	MessageLogoutSuccess         = "Logout successful"
	MessageRegistrationSuccess   = "Registration successful"
	MessagePasswordChangeSuccess = "Password changed successfully"
	MessagePasswordResetSent     = "Password reset email sent"
	MessagePasswordResetSuccess  = "Password reset successful"
	MessageTokenRefreshed        = "Token refreshed successfully"
	MessageTokenValid            = "Token is valid"
	MessageTokenInvalid          = "Token is invalid"
	MessageUserNotFound          = "User not found"
	MessageInvalidCredentials    = "Invalid email or password"
	MessageUserInactive          = "User account is inactive"
	MessageEmailNotVerified      = "Email not verified"
	MessageEmailAlreadyExists    = "Email already exists"
	MessageSessionExpired        = "Session expired"
	MessageInvalidToken          = "Invalid token"
	MessageTokenExpired          = "Token expired"
	MessageInvalidRequest        = "Invalid request data"
	MessageInternalError         = "Internal server error"
)

// GetTokenType returns token type from claims
func (c *TokenClaims) GetTokenType() string {
	if c.TokenType == "" {
		return TokenTypeAccess
	}
	return c.TokenType
}

// IsExpired checks if token is expired
func (c *TokenClaims) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsAccessToken checks if token is access token
func (c *TokenClaims) IsAccessToken() bool {
	return c.GetTokenType() == TokenTypeAccess
}

// IsRefreshToken checks if token is refresh token
func (c *TokenClaims) IsRefreshToken() bool {
	return c.GetTokenType() == TokenTypeRefresh
}

// IsResetToken checks if token is reset token
func (c *TokenClaims) IsResetToken() bool {
	return c.GetTokenType() == TokenTypeReset
}

// IsExpired checks if password reset token is expired
func (p *PasswordResetToken) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// IsUsed checks if password reset token is already used
func (p *PasswordResetToken) IsUsed() bool {
	return p.Used
}

// IsValid checks if password reset token is valid
func (p *PasswordResetToken) IsValid() bool {
	return !p.IsExpired() && !p.IsUsed()
}

// MarkAsUsed marks password reset token as used
func (p *PasswordResetToken) MarkAsUsed() {
	now := time.Now()
	p.Used = true
	p.UsedAt = &now
}
