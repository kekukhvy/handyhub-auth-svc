package utils

import (
	"errors"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey              string
	accessTokenExpiration  time.Duration
	refreshTokenExpiration time.Duration
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, accessTokenExp, refreshTokenExp int) *JWTManager {
	return &JWTManager{
		secretKey:              secretKey,
		accessTokenExpiration:  time.Duration(accessTokenExp) * time.Minute,
		refreshTokenExpiration: time.Duration(refreshTokenExp) * time.Minute,
	}
}

// Claims represents JWT claims structure
type Claims struct {
	UserID    string `json:"userId"`
	SessionID string `json:"sessionId"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	TokenType string `json:"tokenType"`
	jwt.RegisteredClaims
}

// GenerateAccessToken generates an access token for user
func (j *JWTManager) GenerateAccessToken(userID primitive.ObjectID, sessionID, email, role string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(j.accessTokenExpiration)

	claims := &Claims{
		UserID:    userID.Hex(),
		SessionID: sessionID,
		Email:     email,
		Role:      role,
		TokenType: models.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "handyhub-auth-svc",
			Subject:   userID.Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", time.Time{}, models.ErrTokenGenerating
	}

	return tokenString, expiresAt, nil
}

// GenerateRefreshToken generates a refresh token for user
func (j *JWTManager) GenerateRefreshToken(userID primitive.ObjectID, sessionID string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(j.refreshTokenExpiration)

	claims := &Claims{
		UserID:    userID.Hex(),
		SessionID: sessionID,
		TokenType: models.TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "handyhub-auth-svc",
			Subject:   userID.Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", time.Time{}, models.ErrTokenGenerating
	}

	return tokenString, expiresAt, nil
}

// GenerateResetToken generates a password reset token
func (j *JWTManager) GenerateResetToken(userID primitive.ObjectID, email string) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(1 * time.Hour) // Reset tokens expire in 1 hour

	claims := &Claims{
		UserID:    userID.Hex(),
		Email:     email,
		TokenType: models.TokenTypeReset,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "handyhub-auth-svc",
			Subject:   userID.Hex(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(j.secretKey))
	if err != nil {
		return "", time.Time{}, models.ErrTokenGenerating
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates and parses JWT token
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, models.ErrInvalidToken
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, models.ErrTokenExpired
		}
		return nil, models.ErrInvalidToken
	}

	if !token.Valid {
		return nil, models.ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, models.ErrInvalidToken
	}

	return claims, nil
}

// ValidateAccessToken validates access token specifically
func (j *JWTManager) ValidateAccessToken(tokenString string) (*Claims, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != models.TokenTypeAccess {
		return nil, models.ErrInvalidTokenType
	}

	return claims, nil
}

// ValidateRefreshToken validates refresh token specifically
func (j *JWTManager) ValidateRefreshToken(tokenString string) (*Claims, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != models.TokenTypeRefresh {
		return nil, models.ErrInvalidTokenType
	}

	return claims, nil
}

// ValidateResetToken validates password reset token specifically
func (j *JWTManager) ValidateResetToken(tokenString string) (*Claims, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}

	if claims.TokenType != models.TokenTypeReset {
		return nil, models.ErrInvalidTokenType
	}

	return claims, nil
}

// GetUserIDFromClaims converts string user ID to ObjectID
func GetUserIDFromClaims(claims *Claims) (primitive.ObjectID, error) {
	userID, err := primitive.ObjectIDFromHex(claims.UserID)
	if err != nil {
		return primitive.NilObjectID, models.ErrInvalidUserID
	}
	return userID, nil
}

// ToTokenClaims converts JWT claims to models.TokenClaims
func (c *Claims) ToTokenClaims() (*models.TokenClaims, error) {
	userID, err := primitive.ObjectIDFromHex(c.UserID)
	if err != nil {
		return nil, models.ErrInvalidUserID
	}

	return &models.TokenClaims{
		UserID:    userID,
		SessionID: c.SessionID,
		Email:     c.Email,
		Role:      c.Role,
		TokenType: c.TokenType,
		IssuedAt:  c.IssuedAt.Time,
		ExpiresAt: c.ExpiresAt.Time,
	}, nil
}

// GetTokenExpiration returns token expiration based on type
func (j *JWTManager) GetTokenExpiration(tokenType string) time.Duration {
	switch tokenType {
	case models.TokenTypeAccess:
		return j.accessTokenExpiration
	case models.TokenTypeRefresh:
		return j.refreshTokenExpiration
	case models.TokenTypeReset:
		return 1 * time.Hour
	default:
		return j.accessTokenExpiration
	}
}
