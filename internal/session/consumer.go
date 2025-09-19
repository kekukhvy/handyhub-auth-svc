package session

import (
	"context"
	"encoding/json"
	"fmt"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"

	"github.com/sirupsen/logrus"
	"github.com/streadway/amqp"
)

type Consumer interface {
	Start(ctx context.Context) error
	Stop() error
}

type consumer struct {
	channel        *amqp.Channel
	sessionManager Manager
	cacheService   cache.Service
	config         *config.Configuration
	stopChan       chan struct{}
}

// NewConsumer creates a new activity consumer
func NewConsumer(
	channel *amqp.Channel,
	sessionManager Manager,
	cacheService cache.Service,
	cfg *config.Configuration,
) Consumer {
	return &consumer{
		channel:        channel,
		sessionManager: sessionManager,
		cacheService:   cacheService,
		config:         cfg,
		stopChan:       make(chan struct{}),
	}
}

func (c *consumer) Start(ctx context.Context) error {
	log.WithField("queue", c.config.Messaging.Queues.UserActivity.Name).Info("Starting user activity consumer")

	// Declare the queue
	_, err := c.channel.QueueDeclare(
		c.config.Messaging.Queues.UserActivity.Name,
		c.config.Messaging.RabbitMQ.Durable,
		c.config.Messaging.RabbitMQ.AutoDelete,
		c.config.Messaging.RabbitMQ.Exclusive,
		c.config.Messaging.RabbitMQ.NoWait,
		nil, // arguments
	)
	if err != nil {
		log.WithError(err).Error("Failed to declare activity queue")
		return err
	}

	// Bind queue to exchange with routing key pattern
	err = c.channel.QueueBind(
		c.config.Messaging.Queues.UserActivity.Name,       // queue name
		c.config.Messaging.Queues.UserActivity.RoutingKey, // routing key pattern from config
		c.config.Messaging.RabbitMQ.Exchange,              // exchange name
		false,                                             // no-wait
		nil,                                               // arguments
	)
	if err != nil {
		log.WithError(err).Error("Failed to bind queue to exchange")
		return err
	}

	log.WithFields(logrus.Fields{
		"queue":       c.config.Messaging.Queues.UserActivity.Name,
		"exchange":    c.config.Messaging.RabbitMQ.Exchange,
		"routing_key": c.config.Messaging.Queues.UserActivity.RoutingKey,
	}).Info("Queue bound to exchange successfully")

	// Set QoS to process messages one at a time
	err = c.channel.Qos(
		c.config.Messaging.RabbitMQ.PrefetchCount,
		c.config.Messaging.RabbitMQ.PrefetchSize,
		c.config.Messaging.RabbitMQ.Global,
	)
	if err != nil {
		log.WithError(err).Error("Failed to set QoS")
		return err
	}

	messages, err := c.channel.Consume(
		c.config.Messaging.Queues.UserActivity.Name,
		c.config.Messaging.Queues.UserActivity.Consumer,
		c.config.Messaging.RabbitMQ.AutoAck,
		c.config.Messaging.RabbitMQ.Exclusive,
		c.config.Messaging.RabbitMQ.NoLocal,
		c.config.Messaging.RabbitMQ.NoWait,
		nil, // args
	)
	if err != nil {
		log.WithError(err).Error("Failed to start consuming messages")
		return err
	}

	go c.processMessages(ctx, messages)

	log.Info("User activity consumer started successfully")
	return nil
}

// Stop stops the consumer
func (c *consumer) Stop() error {
	log.Info("Stopping user activity consumer")
	close(c.stopChan)
	return nil
}

func (c *consumer) processMessages(ctx context.Context, messages <-chan amqp.Delivery) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Context cancelled, stopping message processing")
			return
		case <-c.stopChan:
			log.Info("Stop signal received, stopping message processing")
			return
		case delivery, ok := <-messages:
			if !ok {
				log.Warn("ActivityMessage channel closed")
				return
			}

			if err := c.handleMessage(ctx, delivery); err != nil {
				log.WithError(err).Error("Failed to process activity message")
				delivery.Nack(false, true) // Nack and requeue
			} else {
				delivery.Ack(false) // Acknowledge successful processing
			}
		}
	}
}

func (c *consumer) handleMessage(ctx context.Context, delivery amqp.Delivery) error {
	log.WithFields(logrus.Fields{
		"delivery_tag": delivery.DeliveryTag,
		"routing_key":  delivery.RoutingKey,
	}).Debug("Processing activity message")

	var msg models.ActivityMessage
	if err := json.Unmarshal(delivery.Body, &msg); err != nil {
		log.WithError(err).Error("Failed to unmarshal activity message")
		return err
	}

	if err := c.validateMessage(&msg); err != nil {
		log.WithError(err).Error("Invalid activity message")
		return err
	}

	if err := c.processActivityUpdate(ctx, &msg); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"user_id":    msg.UserID,
			"session_id": msg.SessionID,
			"service":    msg.ServiceName,
			"action":     msg.Action,
		}).Error("Failed to process activity update")
		return err
	}

	c.logSuccessfulProcessing(&msg)
	return nil
}

// validateMessage validates the activity message format
func (c *consumer) validateMessage(msg *models.ActivityMessage) error {
	if msg.UserID == "" {
		return models.ErrInvalidUserID
	}

	if msg.SessionID == "" {
		return models.ErrInvalidSessionID
	}

	if msg.ServiceName == "" {
		return models.ErrInvalidValue
	}
	return nil
}

// processActivityUpdate processes the user activity update
func (c *consumer) processActivityUpdate(ctx context.Context, msg *models.ActivityMessage) error {
	cacheKey := fmt.Sprintf("session:%s:%s", msg.UserID, msg.SessionID)

	if err := c.cacheService.UpdateSessionActivity(ctx, cacheKey); err != nil {
		log.WithError(err).WithField("session_id", msg.SessionID).Warn("Failed to update session activity in cache")
	}

	if err := c.sessionManager.UpdateSessionActivity(ctx, msg); err != nil {
		log.WithError(err).WithField("session_id", msg.SessionID).Error("Failed to update session activity in database")
		return err
	}

	return nil
}

func (c *consumer) logSuccessfulProcessing(msg *models.ActivityMessage) {
	log.WithFields(logrus.Fields{
		"user_id":    msg.UserID,
		"session_id": msg.SessionID,
		"service":    msg.ServiceName,
		"action":     msg.Action,
		"ip_address": msg.IPAddress,
		"timestamp":  msg.Timestamp,
	}).Debug("Activity message processed successfully")
}
