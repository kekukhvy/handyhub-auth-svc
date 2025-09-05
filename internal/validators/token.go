package validators

import (
	"handyhub-auth-svc/internal/models"
	"regexp"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// TokenValidator handles validation of various token formats (no cryptographic operations)
type TokenValidator struct {
	jwtRegex    *regexp.Regexp
	uuidRegex   *regexp.Regexp
	base64Regex *regexp.Regexp
}

// NewTokenValidator creates a new token validator
func NewTokenValidator() *TokenValidator {
	// JWT token pattern (3 base64url encoded parts separated by dots)
	jwtRegex := regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

	// UUID pattern
	uuidRegex := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

	// Base64 pattern
	base64Regex := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

	return &TokenValidator{
		jwtRegex:    jwtRegex,
		uuidRegex:   uuidRegex,
		base64Regex: base64Regex,
	}
}

// ValidateJWTFormat validates JWT token format only (without signature verification)
func (tv *TokenValidator) ValidateJWTFormat(token string) error {
	if token == "" {
		return models.ErrInvalidToken
	}

	// Remove Bearer prefix if present
	token = tv.stripBearerPrefix(token)

	// Check JWT format
	if !tv.jwtRegex.MatchString(token) {
		return models.ErrTokenMalformed
	}

	// Split into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return models.ErrTokenMalformed
	}

	// Validate each part is valid base64url
	for _, part := range parts {
		if !tv.isValidBase64URL(part) {
			return models.ErrTokenMalformed
		}
	}

	return nil
}

// ValidateSessionID validates session ID format
func (tv *TokenValidator) ValidateSessionID(sessionID string) error {
	if sessionID == "" {
		return models.ErrInvalidSessionID
	}

	// Session IDs should have prefix "sess_" followed by UUID
	if !strings.HasPrefix(sessionID, "sess_") {
		return models.ErrInvalidSessionID
	}

	uuidPart := strings.TrimPrefix(sessionID, "sess_")
	if !tv.uuidRegex.MatchString(uuidPart) {
		return models.ErrInvalidSessionID
	}

	return nil
}

// ValidateUserID validates MongoDB ObjectID format
func (tv *TokenValidator) ValidateUserID(userID string) error {
	if userID == "" {
		return models.ErrInvalidUserID
	}

	if !primitive.IsValidObjectID(userID) {
		return models.ErrInvalidUserID
	}

	return nil
}

// ValidateAuthorizationHeader validates Authorization header format
func (tv *TokenValidator) ValidateAuthorizationHeader(authHeader string) error {
	if authHeader == "" {
		return models.ErrInvalidToken
	}

	// Check Bearer format
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return models.ErrInvalidToken
	}

	// Extract token part
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == "" {
		return models.ErrInvalidToken
	}

	// Validate JWT format only
	return tv.ValidateJWTFormat(token)
}

// ValidateTokenType validates if token type is supported
func (tv *TokenValidator) ValidateTokenType(tokenType string) error {
	validTypes := map[string]bool{
		models.TokenTypeAccess:  true,
		models.TokenTypeRefresh: true,
		models.TokenTypeReset:   true,
	}

	if !validTypes[tokenType] {
		return models.ErrInvalidTokenType
	}

	return nil
}

// ValidateTokenExpiration checks if token expiration time is valid
func (tv *TokenValidator) ValidateTokenExpiration(expiresAt time.Time) error {
	if expiresAt.IsZero() {
		return models.ErrInvalidToken
	}

	if time.Now().After(expiresAt) {
		return models.ErrTokenExpired
	}

	return nil
}

// ExtractTokenFromHeader extracts token from Authorization header
func (tv *TokenValidator) ExtractTokenFromHeader(authHeader string) (string, error) {
	if err := tv.ValidateAuthorizationHeader(authHeader); err != nil {
		return "", err
	}

	return tv.stripBearerPrefix(authHeader), nil
}

// ValidateResetTokenTiming validates password reset token timing constraints
func (tv *TokenValidator) ValidateResetTokenTiming(issuedAt, expiresAt time.Time) error {
	// Check if token is expired
	if time.Now().After(expiresAt) {
		return models.ErrTokenExpired
	}

	// Check if token was issued in the future (clock skew protection)
	if issuedAt.After(time.Now().Add(5 * time.Minute)) {
		return models.ErrInvalidToken
	}

	// Reset tokens should not be valid for more than 24 hours
	maxValidDuration := 24 * time.Hour
	if expiresAt.Sub(issuedAt) > maxValidDuration {
		return models.ErrInvalidToken
	}

	return nil
}

// GetTokenAge calculates token age from issued timestamp
func (tv *TokenValidator) GetTokenAge(issuedAt time.Time) time.Duration {
	return time.Since(issuedAt)
}

// IsTokenNearExpiry checks if token is close to expiring
func (tv *TokenValidator) IsTokenNearExpiry(expiresAt time.Time, threshold time.Duration) bool {
	return time.Until(expiresAt) < threshold
}

// SanitizeToken removes any potentially harmful characters from token
func (tv *TokenValidator) SanitizeToken(token string) string {
	// Remove null bytes and control characters
	token = strings.ReplaceAll(token, "\x00", "")
	token = strings.TrimSpace(token)
	return token
}

// stripBearerPrefix removes "Bearer " prefix from token
func (tv *TokenValidator) stripBearerPrefix(token string) string {
	if strings.HasPrefix(token, "Bearer ") {
		return strings.TrimPrefix(token, "Bearer ")
	}
	return token
}

// isValidBase64URL checks if string is valid base64url encoding
func (tv *TokenValidator) isValidBase64URL(s string) bool {
	// Base64URL uses different characters than standard base64
	base64URLRegex := regexp.MustCompile(`^[A-Za-z0-9_-]*$`)
	return base64URLRegex.MatchString(s)
}
