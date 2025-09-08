package email

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
)

type VerificationEmailData struct {
	FirstName        string
	VerificationLink string
}

type PasswordResetEmailData struct {
	FirstName string
	ResetLink string
}

func RenderVerificationEmail(firstName, verificationToken, frontendUrl string) (subject, htmlBody string, err error) {
	// Prepare data
	data := VerificationEmailData{
		FirstName:        firstName,
		VerificationLink: fmt.Sprintf("%s/auth/verify-email?token=%s", frontendUrl, verificationToken),
	}

	subject = "Verify Your Email Address - HandyHub"

	// Load and parse template file
	templatePath := filepath.Join("templates", "verification.html")

	// Check if file exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("template file not found: %s", templatePath)
	}

	// Parse template
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse template: %w", err)
	}

	// Execute template with data
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute template: %w", err)
	}

	htmlBody = buf.String()
	return subject, htmlBody, nil
}

func RenderPasswordResetEmail(firstName, resetToken, frontendUrl string) (subject, htmlBody string, err error) {
	data := PasswordResetEmailData{
		FirstName: firstName,
		ResetLink: fmt.Sprintf("%s/reset-password?token=%s", frontendUrl, resetToken),
	}

	subject = "Reset Your Password - HandyHub"

	templatePath := filepath.Join("templates", "reset-password.html")
	// Check if file exists
	if _, err := os.Stat(templatePath); os.IsNotExist(err) {
		return "", "", fmt.Errorf("template file not found: %s", templatePath)
	}

	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("failed to execute template: %w", err)
	}

	htmlBody = buf.String()
	return subject, htmlBody, nil
}
