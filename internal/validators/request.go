package validators

import (
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"regexp"
	"strings"
)

// RequestValidator handles validation of API request data
type RequestValidator struct {
	emailValidator    *EmailValidator
	passwordValidator *PasswordValidator
	tokenValidator    *TokenValidator
	phoneRegex        *regexp.Regexp
	nameRegex         *regexp.Regexp
}

// NewRequestValidator creates a new request validator with all sub-validators
func NewRequestValidator(cfg *config.Configuration) *RequestValidator {
	// Phone regex for international format (E.164)
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)

	// Name regex allowing Unicode letters, spaces, hyphens, apostrophes, and periods
	nameRegex := regexp.MustCompile(`^[\p{L}\s\-'.]+$`)

	return &RequestValidator{
		emailValidator:    NewEmailValidator(),
		passwordValidator: NewPasswordValidator(&cfg.Security.PasswordValidation),
		tokenValidator:    NewTokenValidator(),
		phoneRegex:        phoneRegex,
		nameRegex:         nameRegex,
	}
}

// ValidateLoginRequest validates login request data
func (rv *RequestValidator) ValidateLoginRequest(req *models.LoginRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate email
	if err := rv.emailValidator.Validate(req.Email); err != nil {
		errors.Add("email", "email", req.Email, "Invalid email format")
	}

	// Validate password
	if len(req.Password) == 0 {
		errors.Add("password", "required", "", "Password is required")
	} else if len(req.Password) < 6 {
		errors.Add("password", "min", "", "Password must be at least 6 characters")
	} else if len(req.Password) > 128 {
		errors.Add("password", "max", "", "Password is too long")
	}

	return errors
}

// ValidateRegisterRequest validates registration request data
func (rv *RequestValidator) ValidateRegisterRequest(req *models.RegisterRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate first name
	if err := rv.validateName(req.FirstName, "firstName"); err != nil {
		errors.Add("firstName", "name", req.FirstName, err.Error())
	}

	// Validate last name
	if err := rv.validateName(req.LastName, "lastName"); err != nil {
		errors.Add("lastName", "name", req.LastName, err.Error())
	}

	// Validate email
	if err := rv.emailValidator.Validate(req.Email); err != nil {
		errors.Add("email", "email", req.Email, "Invalid email format")
	}

	// Validate password
	if err := rv.passwordValidator.Validate(req.Password); err != nil {
		switch err {
		case models.ErrPasswordTooShort:
			errors.Add("password", "min", "", "Password is too short")
		case models.ErrPasswordTooWeak:
			errors.Add("password", "weak", "", "Password is too weak")
		default:
			errors.Add("password", "invalid", "", "Invalid password")
		}
	}

	// Check for common passwords
	if rv.passwordValidator.IsCommonPassword(req.Password) {
		errors.Add("password", "common", "", "Password is too common")
	}

	// Validate phone (optional)
	if req.Phone != "" {
		if err := rv.validatePhone(req.Phone); err != nil {
			errors.Add("phone", "phone", req.Phone, "Invalid phone number format")
		}
	}

	// Validate language (optional)
	if req.Language != "" {
		if err := rv.validateLanguage(req.Language); err != nil {
			errors.Add("language", "language", req.Language, "Invalid language code")
		}
	}

	// Validate timezone (optional)
	if req.TimeZone != "" {
		if err := rv.validateTimeZone(req.TimeZone); err != nil {
			errors.Add("timeZone", "timezone", req.TimeZone, "Invalid timezone")
		}
	}

	return errors
}

// ValidateChangePasswordRequest validates password change request
func (rv *RequestValidator) ValidateChangePasswordRequest(req *models.ChangePasswordRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate current password
	if len(req.CurrentPassword) == 0 {
		errors.Add("currentPassword", "required", "", "Current password is required")
	}

	// Validate new password
	if err := rv.passwordValidator.Validate(req.NewPassword); err != nil {
		switch err {
		case models.ErrPasswordTooShort:
			errors.Add("newPassword", "min", "", "New password is too short")
		case models.ErrPasswordTooWeak:
			errors.Add("newPassword", "weak", "", "New password is too weak")
		default:
			errors.Add("newPassword", "invalid", "", "Invalid new password")
		}
	}

	// Check if new password is same as current
	if req.CurrentPassword == req.NewPassword {
		errors.Add("newPassword", "same", "", "New password must be different from current password")
	}

	// Check for common passwords
	if rv.passwordValidator.IsCommonPassword(req.NewPassword) {
		errors.Add("newPassword", "common", "", "New password is too common")
	}

	return errors
}

// ValidateResetPasswordRequest validates password reset request
func (rv *RequestValidator) ValidateResetPasswordRequest(req *models.ResetPasswordRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate email
	if err := rv.emailValidator.Validate(req.Email); err != nil {
		errors.Add("email", "email", req.Email, "Invalid email format")
	}

	return errors
}

// ValidateResetPasswordConfirmRequest validates password reset confirmation
func (rv *RequestValidator) ValidateResetPasswordConfirmRequest(req *models.ResetPasswordConfirmRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate reset token
	if len(req.Token) == 0 {
		errors.Add("token", "required", "", "Reset token is required")
	} else if err := rv.tokenValidator.ValidateJWTFormat(req.Token); err != nil {
		errors.Add("token", "format", "", "Invalid token format")
	}

	// Validate new password
	if err := rv.passwordValidator.Validate(req.NewPassword); err != nil {
		switch err {
		case models.ErrPasswordTooShort:
			errors.Add("newPassword", "min", "", "Password is too short")
		case models.ErrPasswordTooWeak:
			errors.Add("newPassword", "weak", "", "Password is too weak")
		default:
			errors.Add("newPassword", "invalid", "", "Invalid password")
		}
	}

	// Check for common passwords
	if rv.passwordValidator.IsCommonPassword(req.NewPassword) {
		errors.Add("newPassword", "common", "", "Password is too common")
	}

	return errors
}

// ValidateRefreshTokenRequest validates token refresh request
func (rv *RequestValidator) ValidateRefreshTokenRequest(req *models.RefreshTokenRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate refresh token format
	if len(req.RefreshToken) == 0 {
		errors.Add("refreshToken", "required", "", "Refresh token is required")
	} else if err := rv.tokenValidator.ValidateJWTFormat(req.RefreshToken); err != nil {
		errors.Add("refreshToken", "format", "", "Invalid refresh token format")
	}

	return errors
}

// ValidateVerifyTokenRequest validates token verification request
func (rv *RequestValidator) ValidateVerifyTokenRequest(req *models.VerifyTokenRequest) *models.ValidationErrors {
	errors := &models.ValidationErrors{}

	// Validate token
	if len(req.Token) == 0 {
		errors.Add("token", "required", "", "Token is required")
	} else if err := rv.tokenValidator.ValidateJWTFormat(req.Token); err != nil {
		errors.Add("token", "format", "", "Invalid token format")
	}

	return errors
}

// validateName validates first name or last name
func (rv *RequestValidator) validateName(name, fieldName string) error {
	if name == "" {
		return models.ErrInvalidParams
	}

	name = strings.TrimSpace(name)

	if len(name) < 2 {
		return models.ErrInvalidParams
	}

	if len(name) > 50 {
		return models.ErrInvalidParams
	}

	// Check for valid characters
	if !rv.nameRegex.MatchString(name) {
		return models.ErrInvalidParams
	}

	return nil
}

// validatePhone validates phone number format
func (rv *RequestValidator) validatePhone(phone string) error {
	if phone == "" {
		return nil // Phone is optional
	}

	// Remove common formatting characters
	cleanPhone := strings.ReplaceAll(phone, " ", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "-", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, "(", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ")", "")
	cleanPhone = strings.ReplaceAll(cleanPhone, ".", "")

	if !rv.phoneRegex.MatchString(cleanPhone) {
		return models.ErrInvalidParams
	}

	return nil
}

// validateLanguage validates language code (ISO 639-1)
func (rv *RequestValidator) validateLanguage(language string) error {
	if language == "" {
		return nil // Optional field
	}

	// Common language codes
	validLanguages := map[string]bool{
		"en": true, "es": true, "fr": true, "de": true, "it": true,
		"pt": true, "ru": true, "zh": true, "ja": true, "ko": true,
		"ar": true, "hi": true, "tr": true, "pl": true, "nl": true,
		"sv": true, "da": true, "no": true, "fi": true, "uk": true,
		"cs": true, "sk": true, "hu": true, "ro": true, "bg": true,
	}

	if !validLanguages[strings.ToLower(language)] {
		return models.ErrInvalidParams
	}

	return nil
}

// validateTimeZone validates timezone string (basic validation)
func (rv *RequestValidator) validateTimeZone(timezone string) error {
	if timezone == "" {
		return nil // Optional field
	}

	// Basic timezone validation
	if len(timezone) < 3 || len(timezone) > 50 {
		return models.ErrInvalidParams
	}

	// Common timezone patterns
	timezoneRegex := regexp.MustCompile(`^[A-Za-z]+/[A-Za-z_]+$|^UTC$|^GMT[+-]\d{1,2}$`)
	if !timezoneRegex.MatchString(timezone) {
		return models.ErrInvalidParams
	}

	return nil
}

// SanitizeString removes potentially harmful characters and trims whitespace
func (rv *RequestValidator) SanitizeString(input string) string {
	// Remove null bytes and control characters
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// SanitizeLoginRequest sanitizes login request data
func (rv *RequestValidator) SanitizeLoginRequest(req *models.LoginRequest) {
	req.Email = rv.emailValidator.Normalize(req.Email)
	req.Password = rv.SanitizeString(req.Password)
}

// SanitizeRegisterRequest sanitizes registration request data
func (rv *RequestValidator) SanitizeRegisterRequest(req *models.RegisterRequest) {
	req.FirstName = rv.sanitizeName(req.FirstName)
	req.LastName = rv.sanitizeName(req.LastName)
	req.Email = rv.emailValidator.Normalize(req.Email)
	req.Password = rv.SanitizeString(req.Password)
	req.Phone = rv.sanitizePhone(req.Phone)
	req.Language = strings.ToLower(rv.SanitizeString(req.Language))
	req.TimeZone = rv.SanitizeString(req.TimeZone)
}

// sanitizeName normalizes name (capitalize first letter of each word)
func (rv *RequestValidator) sanitizeName(name string) string {
	name = rv.SanitizeString(name)
	if len(name) == 0 {
		return name
	}

	words := strings.Fields(name)
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(string(word[0])) + strings.ToLower(word[1:])
		}
	}

	return strings.Join(words, " ")
}

// sanitizePhone removes formatting from phone number
func (rv *RequestValidator) sanitizePhone(phone string) string {
	if phone == "" {
		return phone
	}

	// Remove common formatting characters but keep the + for country code
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	phone = strings.ReplaceAll(phone, "(", "")
	phone = strings.ReplaceAll(phone, ")", "")
	phone = strings.ReplaceAll(phone, ".", "")

	return rv.SanitizeString(phone)
}

// ValidateAndSanitizeRequest validates and sanitizes any request
func (rv *RequestValidator) ValidateAndSanitizeRequest(req interface{}) *models.ValidationErrors {
	switch r := req.(type) {
	case *models.LoginRequest:
		rv.SanitizeLoginRequest(r)
		return rv.ValidateLoginRequest(r)
	case *models.RegisterRequest:
		rv.SanitizeRegisterRequest(r)
		return rv.ValidateRegisterRequest(r)
	case *models.ChangePasswordRequest:
		return rv.ValidateChangePasswordRequest(r)
	case *models.ResetPasswordRequest:
		return rv.ValidateResetPasswordRequest(r)
	case *models.ResetPasswordConfirmRequest:
		return rv.ValidateResetPasswordConfirmRequest(r)
	case *models.RefreshTokenRequest:
		return rv.ValidateRefreshTokenRequest(r)
	case *models.VerifyTokenRequest:
		return rv.ValidateVerifyTokenRequest(r)
	default:
		errors := &models.ValidationErrors{}
		errors.Add("request", "type", "", "Unsupported request type")
		return errors
	}
}
