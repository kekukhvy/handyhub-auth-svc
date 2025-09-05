package validators

import (
	"handyhub-auth-svc/internal/models"
	"net/mail"
	"regexp"
	"strings"
)

// EmailValidator handles email validation and normalization
type EmailValidator struct {
	emailRegex          *regexp.Regexp
	disposableEmailList map[string]bool
}

// NewEmailValidator creates a new email validator
func NewEmailValidator() *EmailValidator {
	// More strict email regex than the standard one
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	disposableEmails := map[string]bool{
		"10minutemail.com":  true,
		"guerrillamail.com": true,
		"mailinator.com":    true,
		"tempmail.org":      true,
		"throwaway.email":   true,
		"temp-mail.org":     true,
		"getnada.com":       true,
		"mailnesia.com":     true,
	}

	return &EmailValidator{
		emailRegex:          emailRegex,
		disposableEmailList: disposableEmails,
	}
}

func (ev *EmailValidator) Validate(email string) error {
	if email == "" {
		return models.ErrInvalidEmail
	}

	normalizedEmail := ev.Normalize(email)

	if err := ev.validateFormat(normalizedEmail); err != nil {
		return err
	}

	if err := ev.validateLength(normalizedEmail); err != nil {
		return err
	}

	if err := ev.validateDomain(normalizedEmail); err != nil {
		return err
	}

	if ev.IsDisposable(normalizedEmail) {
		return models.ErrInvalidEmail
	}

	return nil
}

// ValidateFormat checks email format using multiple methods
func (ev *EmailValidator) validateFormat(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return models.ErrInvalidEmail
	}

	if !ev.emailRegex.MatchString(email) {
		return models.ErrInvalidEmail
	}

	return nil
}

// validateLength checks if email length is within acceptable limits
func (ev *EmailValidator) validateLength(email string) error {
	// RFC 5321 specifies maximum length of 320 characters
	// But we use 254 as practical limit
	if len(email) > 254 {
		return models.ErrInvalidEmail
	}

	localPart := ev.GetLocalPart(email)
	domain := ev.GetDomain(email)

	// Local part should be between 1-64 characters
	if len(localPart) < 1 || len(localPart) > 64 {
		return models.ErrInvalidEmail
	}

	// Domain should be between 1-253 characters
	if len(domain) < 1 || len(domain) > 253 {
		return models.ErrInvalidEmail
	}

	return nil
}

// validateDomain performs basic domain validation
func (ev *EmailValidator) validateDomain(email string) error {

	domain := ev.GetDomain(email)

	// Domain must contain at least one dot
	if !strings.Contains(domain, ".") {
		return models.ErrInvalidEmail
	}

	// Check for valid domain format
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !domainRegex.MatchString(domain) {
		return models.ErrInvalidEmail
	}

	// Check for consecutive dots
	if strings.Contains(domain, "..") {
		return models.ErrInvalidEmail
	}

	// Domain cannot start or end with hyphen or dot
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return models.ErrInvalidEmail
	}

	return nil
}

// Normalize converts email to standard format
func (ev *EmailValidator) Normalize(email string) string {
	email = strings.TrimSpace(email)
	email = strings.ToLower(email)
	email = strings.ReplaceAll(email, "\x00", "")
	return email
}

// IsDisposable checks if email domain is a known disposable email provider
func (ev *EmailValidator) IsDisposable(email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	domain := strings.ToLower(parts[1])
	return ev.disposableEmailList[domain]
}

// GetDomain extracts domain from email address
func (ev *EmailValidator) GetDomain(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return strings.ToLower(parts[1])
}

// GetLocalPart extracts local part from email address
func (ev *EmailValidator) GetLocalPart(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

// IsValidEmailDomain checks if domain is valid for email
func (ev *EmailValidator) IsValidEmailDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic domain validation
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// SuggestCorrection suggests common email corrections (basic implementation)
func (ev *EmailValidator) SuggestCorrection(email string) string {
	email = ev.Normalize(email)

	// Common typo corrections
	corrections := map[string]string{
		"gmial.com":   "gmail.com",
		"gmai.com":    "gmail.com",
		"gmail.co":    "gmail.com",
		"hotmial.com": "hotmail.com",
		"hotmai.com":  "hotmail.com",
		"yahooo.com":  "yahoo.com",
		"yahoo.co":    "yahoo.com",
		"outlok.com":  "outlook.com",
		"outloo.com":  "outlook.com",
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	domain := parts[1]
	if corrected, exists := corrections[domain]; exists {
		return parts[0] + "@" + corrected
	}

	return email
}

// ValidateAndNormalize performs validation and returns normalized email
func (ev *EmailValidator) ValidateAndNormalize(email string) (string, error) {
	normalized := ev.Normalize(email)
	if err := ev.Validate(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}
