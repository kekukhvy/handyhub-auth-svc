package validators

import (
	"fmt"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"strings"
	"unicode"

	"github.com/sirupsen/logrus"
)

// PasswordValidator handles password strength validation
var log = logrus.StandardLogger()

type PasswordValidator struct {
	minLength           int
	maxLength           int
	requireUppercase    bool
	requireLowercase    bool
	requireDigits       bool
	requireSpecialChars bool
	minSpecialChars     int
	forbiddenPatterns   []string
	commonPasswords     map[string]bool
	maxCharRepeat       int
	maxSequentialChars  int
}

// NewPasswordValidator creates a new password validator with default rules
func NewPasswordValidator(validation *config.PasswordValidation) *PasswordValidator {
	commonPasswords := map[string]bool{
		"password":    true,
		"123456":      true,
		"123456789":   true,
		"qwerty":      true,
		"abc123":      true,
		"password123": true,
		"admin":       true,
		"letmein":     true,
		"welcome":     true,
		"monkey":      true,
		"dragon":      true,
		"sunshine":    true,
		"princess":    true,
		"football":    true,
		"basketball":  true,
		"superman":    true,
		"iloveyou":    true,
		"trustno1":    true,
	}

	return &PasswordValidator{
		minLength:           validation.MinLength,
		maxLength:           128,
		requireUppercase:    validation.RequireUppercase,
		requireLowercase:    validation.RequireLowercase,
		requireDigits:       validation.RequireNumber,
		requireSpecialChars: validation.RequireSpecial,
		minSpecialChars:     1,
		forbiddenPatterns:   []string{"password", "admin", "user", "login"},
		commonPasswords:     commonPasswords,
		maxCharRepeat:       validation.MaxCharRepeats,
		maxSequentialChars:  validation.MaxSequentialChars,
	}
}

// Validate performs comprehensive password validation
func (pv *PasswordValidator) Validate(password string) error {
	if err := pv.validateLength(password); err != nil {
		return err
	}

	if err := pv.validateCharacterRequirements(password); err != nil {
		return err
	}

	if err := pv.validateForbiddenPatterns(password); err != nil {
		return err
	}

	if pv.IsCommonPassword(password) {
		return models.ErrPasswordTooWeak
	}

	if err := pv.validateComplexity(password); err != nil {
		return err
	}

	return nil
}

// validateLength checks password length requirements
func (pv *PasswordValidator) validateLength(password string) error {
	if len(password) < pv.minLength {
		return models.ErrPasswordTooShort
	}

	if len(password) > pv.maxLength {
		return models.ErrInvalidPassword
	}

	return nil
}

// validateCharacterRequirements checks character type requirements
func (pv *PasswordValidator) validateCharacterRequirements(password string) error {
	var (
		hasUpper     = false
		hasLower     = false
		hasDigit     = false
		hasSpecial   = false
		specialCount = 0
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case pv.isSpecialChar(char):
			hasSpecial = true
			specialCount++
		}
	}

	if pv.requireUppercase && !hasUpper {
		return models.ErrPasswordTooWeak
	}

	if pv.requireLowercase && !hasLower {
		return models.ErrPasswordTooWeak
	}

	if pv.requireDigits && !hasDigit {
		return models.ErrPasswordTooWeak
	}

	if pv.requireSpecialChars && (!hasSpecial || specialCount < pv.minSpecialChars) {
		return models.ErrPasswordTooWeak
	}

	return nil
}

// validateForbiddenPatterns checks for forbidden patterns in password
func (pv *PasswordValidator) validateForbiddenPatterns(password string) error {
	lowerPassword := strings.ToLower(password)

	for _, pattern := range pv.forbiddenPatterns {
		if strings.Contains(lowerPassword, strings.ToLower(pattern)) {
			return models.ErrPasswordTooWeak
		}
	}

	return nil
}

// validateComplexity performs additional complexity checks
func (pv *PasswordValidator) validateComplexity(password string) error {
	// Check for repeated characters
	if pv.hasRepeatedChars(password, pv.maxCharRepeat) {
		log.Debug("Password has repeated characters")
		return models.ErrPasswordTooWeak
	}

	// Check for sequential characters
	if pv.hasSequentialChars(password, pv.maxSequentialChars) {
		log.Debug("Password has sequential characters")
		return models.ErrPasswordTooWeak
	}

	// Check for keyboard patterns
	if pv.hasKeyboardPattern(password) {
		log.Debug("Password has keyboard patterns")
		return models.ErrPasswordTooWeak
	}

	return nil
}

// isSpecialChar checks if a character is considered special
func (pv *PasswordValidator) isSpecialChar(char rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"
	for _, special := range specialChars {
		if char == special {
			return true
		}
	}
	return false
}

// hasRepeatedChars checks for consecutive repeated characters
func (pv *PasswordValidator) hasRepeatedChars(password string, maxRepeats int) bool {
	if len(password) < maxRepeats {
		return false
	}

	for i := 0; i < len(password)-maxRepeats+1; i++ {
		char := password[i]
		consecutive := 1

		for j := i + 1; j < len(password) && password[j] == char; j++ {
			consecutive++
			if consecutive >= maxRepeats {
				return true
			}
		}
	}

	return false
}

// hasSequentialChars checks for sequential characters (abc, 123, etc.)
func (pv *PasswordValidator) hasSequentialChars(password string, maxSequential int) bool {
	if len(password) < maxSequential {
		return false
	}

	for i := 0; i < len(password)-maxSequential+1; i++ {
		// Check ascending sequence
		isAscending := true
		for j := 1; j < maxSequential; j++ {
			if password[i+j] != password[i+j-1]+1 {
				isAscending = false
				break
			}
		}

		// Check descending sequence
		isDescending := true
		for j := 1; j < maxSequential; j++ {
			if password[i+j] != password[i+j-1]-1 {
				isDescending = false
				break
			}
		}

		if isAscending || isDescending {
			return true
		}
	}

	return false
}

// hasKeyboardPattern checks for common keyboard patterns
func (pv *PasswordValidator) hasKeyboardPattern(password string) bool {
	keyboardPatterns := []string{
		"qwerty", "asdf", "zxcv", "yuiop", "hjkl", "bnm",
		"1234", "5678", "9012",
		"qwertyuiop", "asdfghjkl", "zxcvbnm",
	}

	lowerPassword := strings.ToLower(password)
	for _, pattern := range keyboardPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return true
		}
	}

	return false
}

// IsCommonPassword checks if password is in the common passwords list
func (pv *PasswordValidator) IsCommonPassword(password string) bool {
	return pv.commonPasswords[strings.ToLower(password)]
}

// GenerateRequirements returns password requirements as strings
func (pv *PasswordValidator) GenerateRequirements() []string {
	requirements := []string{
		fmt.Sprintf("At least %d characters long", pv.minLength),
	}

	if pv.requireUppercase {
		requirements = append(requirements, "At least one uppercase letter")
	}
	if pv.requireLowercase {
		requirements = append(requirements, "At least one lowercase letter")
	}
	if pv.requireDigits {
		requirements = append(requirements, "At least one number")
	}
	if pv.requireSpecialChars {
		if pv.minSpecialChars > 1 {
			requirements = append(requirements, fmt.Sprintf("At least %d special characters", pv.minSpecialChars))
		} else {
			requirements = append(requirements, "At least one special character")
		}
	}

	return requirements
}

// ValidatePasswordMatch checks if two passwords match
func (pv *PasswordValidator) ValidatePasswordMatch(password, confirmPassword string) error {
	if password != confirmPassword {
		return models.ErrPasswordMismatch
	}
	return nil
}
