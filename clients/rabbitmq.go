package clients

import (
	"fmt"
	"handyhub-auth-svc/internal/config"

	"github.com/streadway/amqp"
)

type RabbitMQ struct {
	Conn    *amqp.Connection
	Channel *amqp.Channel
	cfg     *config.RabbitMQConfig
}

func NewRabbitMQ(cfg *config.RabbitMQConfig) (*RabbitMQ, error) {
	log.WithField("url", "url:"+cfg.Url).Info("Connecting to RabbitMQ...")
	conn, err := amqp.Dial(cfg.Url)
	if err != nil {
		log.WithError(err).Errorf("Failed to connect to RabbitMQ: %v", err)
		return nil, err
	}

	channel, err := conn.Channel()
	if err != nil {
		log.WithError(err).Errorf("Failed to open a channel: %v", err)
		return nil, err
	}

	log.Infof("Connected to RabbitMQ at %s", cfg.Url)

	return &RabbitMQ{
		Conn:    conn,
		Channel: channel,
		cfg:     cfg,
	}, nil
}

func (r *RabbitMQ) Close() error {
	if r.Channel != nil {
		if err := r.Channel.Close(); err != nil {
			log.WithError(err).Error("Failed to close RabbitMQ channel")
			return err
		} else {
			log.Info("RabbitMQ channel closed")
			return nil
		}
	}

	if r.Conn != nil {
		if err := r.Conn.Close(); err != nil {
			log.WithError(err).Error("Failed to close RabbitMQ connection")
			return err
		} else {
			log.Info("RabbitMQ connection closed")
			return nil
		}
	}

	return nil
}

func (r *RabbitMQ) SetupQueue() error {
	err := r.Channel.ExchangeDeclare(
		r.cfg.Exchange,
		r.cfg.ExchangeType,
		r.cfg.Durable,
		r.cfg.AutoDelete,
		r.cfg.Internal,
		r.cfg.NoWait,
		nil,
	)

	if err != nil {
		return fmt.Errorf("failed to declare exchange: %v", err)
	}

	return nil
}
