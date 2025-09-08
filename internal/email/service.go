package email

import (
	"encoding/json"
	"fmt"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/config"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

var log = logrus.StandardLogger()

type Service interface {
	SendVerificationEmail(userEmail, firstName, verificationToken string) error
	SendPasswordResetEmail(userEmail, firstName, resetToken string) error
}

type emailService struct {
	config   *config.Configuration
	rabbitMQ *clients.RabbitMQ
}

// EmailMessage represents the structure for email service
type Message struct {
	To       []string          `json:"to"`
	Subject  string            `json:"subject"`
	BodyHTML string            `json:"body_html"`
	BodyText string            `json:"body_text"`
	From     string            `json:"from"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// QueueMessage represents the message structure for RabbitMQ
type QueueMessage struct {
	Email     Message           `json:"email"`
	Priority  string            `json:"priority"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
}

func NewEmailService(cfg *config.Configuration, rabbitMQ *clients.RabbitMQ) Service {
	if !cfg.EmailService.Enabled {
		logrus.Info("Email service disabled - using mock")
		return &mockEmailService{}
	}

	service := &emailService{
		config:   cfg,
		rabbitMQ: rabbitMQ,
	}

	return service
}

func (s *emailService) SendVerificationEmail(userEmail, firstName, verificationToken string) error {
	log.WithField("email", userEmail).Debug("Queueing verification email")

	subject, htmlBody, err := RenderVerificationEmail(firstName, verificationToken, s.config.App.HostLink)
	if err != nil {
		return fmt.Errorf("failed to render email template: %w", err)
	}

	message := QueueMessage{
		Email: Message{
			To:       []string{userEmail},
			Subject:  subject,
			BodyHTML: htmlBody,
		},
		Priority: "high",
		Metadata: map[string]string{
			"type":               "verification",
			"user_email":         userEmail,
			"verification_token": verificationToken,
		},
		Timestamp: time.Now(),
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	err = s.rabbitMQ.Channel.Publish(
		s.config.Queue.RabbitMQ.Exchange,
		s.config.Queue.RabbitMQ.RoutingKey,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
			Timestamp:   time.Now(),
		},
	)

	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	log.WithField("email", userEmail).Info("Verification email queued successfully")

	return nil
}

func (s *emailService) SendPasswordResetEmail(userEmail, firstName, resetToken string) error {
	log.WithField("email", userEmail).Debug("Queueing password reset email")

	subject, htmlBody, err := RenderPasswordResetEmail(firstName, resetToken, s.config.EmailService.FrontendURL)
	if err != nil {
		return fmt.Errorf("failed to render password reset email template: %w", err)
	}

	message := QueueMessage{
		Email: Message{
			To:       []string{userEmail},
			Subject:  subject,
			BodyHTML: htmlBody,
		},
		Priority: "high",
		Metadata: map[string]string{
			"type":        "password_reset",
			"user_email":  userEmail,
			"reset_token": resetToken,
		},
		Timestamp: time.Now(),
	}

	body, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	err = s.rabbitMQ.Channel.Publish(
		s.config.Queue.RabbitMQ.Exchange,
		s.config.Queue.RabbitMQ.RoutingKey,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
			Timestamp:   time.Now(),
		},
	)

	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	log.WithField("email", userEmail).Info("Password reset email queued successfully")
	return nil
}

// Mock implementation
type mockEmailService struct{}

func (m *mockEmailService) SendVerificationEmail(userEmail, firstName, verificationToken string) error {
	logrus.WithFields(logrus.Fields{
		"email": userEmail,
		"token": verificationToken,
	}).Info("Mock: Verification email would be sent")
	return nil
}

func (m *mockEmailService) SendPasswordResetEmail(userEmail, firstName, resetToken string) error {
	logrus.WithFields(logrus.Fields{
		"email": userEmail,
		"token": resetToken,
	}).Info("Mock: Password reset email would be sent")
	return nil
}
