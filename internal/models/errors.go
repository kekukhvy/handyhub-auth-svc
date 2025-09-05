package models

import "errors"

// Authentication errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrUserSuspended      = errors.New("user account is suspended")
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrPhoneAlreadyExists = errors.New("phone number already exists")
)

// Token errors
var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenMalformed   = errors.New("token malformed")
	ErrTokenGenerating  = errors.New("error generating token")
	ErrTokenParsing     = errors.New("error parsing token")
	ErrInvalidTokenType = errors.New("invalid token type")
	ErrTokenNotFound    = errors.New("token not found")
	ErrTokenAlreadyUsed = errors.New("token already used")
)

// Session errors
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrSessionInactive = errors.New("session inactive")
	ErrSessionInvalid  = errors.New("session invalid")
	ErrSessionCreating = errors.New("error creating session")
	ErrSessionUpdating = errors.New("error updating session")
	ErrSessionDeleting = errors.New("error deleting session")
	ErrTooManySessions = errors.New("too many active sessions")
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
	ErrDatabaseConnection = errors.New("database connection error")
	ErrDatabaseQuery      = errors.New("database query error")
	ErrDatabaseInsert     = errors.New("database insert error")
	ErrDatabaseUpdate     = errors.New("database update error")
	ErrDatabaseDelete     = errors.New("database delete error")
	ErrRecordNotFound     = errors.New("record not found")
	ErrDuplicateRecord    = errors.New("duplicate record")
)

// Redis errors
var (
	ErrRedisConnection = errors.New("redis connection error")
	ErrRedisGet        = errors.New("redis get error")
	ErrRedisSet        = errors.New("redis set error")
	ErrRedisDelete     = errors.New("redis delete error")
	ErrRedisExpire     = errors.New("redis expire error")
)

// Rate limiting errors
var (
	ErrRateLimitExceeded     = errors.New("rate limit exceeded")
	ErrTooManyRequests       = errors.New("too many requests")
	ErrLoginAttemptsExceeded = errors.New("too many login attempts")
)

// Generic errors
var (
	ErrInternalServer     = errors.New("internal server error")
	ErrServiceUnavailable = errors.New("service unavailable")
	ErrTimeout            = errors.New("request timeout")
	ErrBadRequest         = errors.New("bad request")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrInvalidRequest     = errors.New("invalid request")
)

// Security errors
var (
	ErrPasswordMismatch   = errors.New("password mismatch")
	ErrWeakPassword       = errors.New("password is too weak")
	ErrPasswordReused     = errors.New("password was recently used")
	ErrInvalidCSRFToken   = errors.New("invalid csrf token")
	ErrInvalidOrigin      = errors.New("invalid origin")
	ErrSuspiciousActivity = errors.New("suspicious activity detected")
	ErrAccountLocked      = errors.New("account temporarily locked")
)

// Password reset errors
var (
	ErrResetTokenExpired   = errors.New("password reset token expired")
	ErrResetTokenInvalid   = errors.New("password reset token invalid")
	ErrResetTokenUsed      = errors.New("password reset token already used")
	ErrResetRequestTooSoon = errors.New("password reset requested too soon")
	ErrResetLimitExceeded  = errors.New("password reset limit exceeded")
)

// Email verification errors
var (
	ErrVerificationTokenExpired  = errors.New("verification token expired")
	ErrVerificationTokenInvalid  = errors.New("verification token invalid")
	ErrEmailAlreadyVerified      = errors.New("email already verified")
	ErrVerificationLimitExceeded = errors.New("verification attempts limit exceeded")
)

// ErrorResponse represents API error response structure
type ErrorResponse struct {
	Status  string      `json:"status"`
	Error   string      `json:"error"`
	Message string      `json:"message"`
	Code    int         `json:"code,omitempty"`
	Details interface{} `json:"details,omitempty"`
}

// SuccessResponse represents API success response structure
type SuccessResponse struct {
	Status  string      `json:"status"`
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
		Status:  StatusError,
		Error:   err.Error(),
		Message: message,
	}
}

// NewErrorResponseWithCode creates a new error response with code
func NewErrorResponseWithCode(err error, message string, code int) *ErrorResponse {
	return &ErrorResponse{
		Status:  StatusError,
		Error:   err.Error(),
		Message: message,
		Code:    code,
	}
}

// NewErrorResponseWithDetails creates a new error response with details
func NewErrorResponseWithDetails(err error, message string, details interface{}) *ErrorResponse {
	return &ErrorResponse{
		Status:  StatusError,
		Error:   err.Error(),
		Message: message,
		Details: details,
	}
}

// NewSuccessResponse creates a new success response
func NewSuccessResponse(message string, data interface{}) *SuccessResponse {
	return &SuccessResponse{
		Status:  StatusSuccess,
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
