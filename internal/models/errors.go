package models

import "errors"

// Authentication errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrEmailAlreadyExists = errors.New("email already exists")
)

// Token errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenMalformed   = errors.New("token malformed")
	ErrTokenGenerating  = errors.New("error generating token")
	ErrInvalidTokenType = errors.New("invalid token type")
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInactive = errors.New("session inactive")
	ErrSessionInvalid  = errors.New("session invalid")
	ErrSessionCreating = errors.New("error creating session")
	ErrSessionUpdating = errors.New("error updating session")
)

// Validation errors
var (
	ErrInvalidValue     = errors.New("invalid value")
	ErrValueTooLong     = errors.New("value too long")
	ErrValueTooShort    = errors.New("value too short")
	ErrInvalidEmail     = errors.New("invalid email format")
	ErrInvalidPassword  = errors.New("invalid password format")
	ErrPasswordTooShort = errors.New("password too short")
	ErrPasswordTooWeak  = errors.New("password too weak")
	ErrInvalidRole      = errors.New("invalid user role")
	ErrInvalidStatus    = errors.New("invalid user status")
	ErrInvalidUserID    = errors.New("invalid user id")
	ErrInvalidSessionID = errors.New("invalid session id")
)

// Database errors
var (
	ErrDatabaseQuery  = errors.New("database query error")
	ErrDatabaseInsert = errors.New("database insert error")
	ErrDatabaseUpdate = errors.New("database update error")
)

// Redis errors
var (
	ErrRedisGet    = errors.New("redis get error")
	ErrRedisSet    = errors.New("redis set error")
	ErrRedisDelete = errors.New("redis delete error")
)

var (
	ErrLoginAttemptsExceeded = errors.New("too many login attempts")
)

// Generic errors
var (
	ErrInternalServer = errors.New("internal server error")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrInvalidRequest = errors.New("invalid request")
)

// Security errors
var (
	ErrPasswordMismatch = errors.New("password mismatch")
)

// Email verification errors
var (
	ErrVerificationTokenExpired = errors.New("verification token expired")
	ErrVerificationTokenInvalid = errors.New("verification token invalid")
	ErrEmailAlreadyVerified     = errors.New("email already verified")
)

// ErrorResponse represents API error response structure
type ErrorResponse struct {
	Success bool        `json:"success"`
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Code    int         `json:"code,omitempty"`
	Details interface{} `json:"details,omitempty"`
}

// SuccessResponse represents API success response structure
type SuccessResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// ValidationError represents field validation error
type ValidationError struct {
	Field   string `json:"field"`
	Tag     string `json:"tag"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// ValidationErrors represents multiple validation errors
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// NewErrorResponse creates a new error response
func NewErrorResponse(err error, message string) *ErrorResponse {
	return &ErrorResponse{
		Success: false,
		Error:   err.Error(),
		Message: message,
	}
}

// NewSuccessResponse creates a new success response
func NewSuccessResponse(message string, data interface{}) *SuccessResponse {
	return &SuccessResponse{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// Error implements error interface for ValidationErrors
func (v ValidationErrors) Error() string {
	if len(v.Errors) == 0 {
		return "validation errors"
	}
	return v.Errors[0].Message
}

// Add adds a validation error
func (v *ValidationErrors) Add(field, tag, value, message string) {
	v.Errors = append(v.Errors, ValidationError{
		Field:   field,
		Tag:     tag,
		Value:   value,
		Message: message,
	})
}

// HasErrors checks if there are validation errors
func (v *ValidationErrors) HasErrors() bool {
	return len(v.Errors) > 0
}
