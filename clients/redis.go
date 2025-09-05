package clients

import (
	"context"
	"handyhub-auth-svc/internal/config"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var log = logrus.StandardLogger()

type RedisClient struct {
	Client *redis.Client
}

func NewRedisClient(cfg *config.Configuration) (*RedisClient, error) {
	log.Info("Connecting to Redis...")

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Url,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.Db,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		log.WithError(err).Errorf("Failed to connect to Redis: %v", err)
		return nil, err
	}

	log.Infof("Connected to Redis at %s", cfg.Redis.Url)

	return &RedisClient{
		Client: client,
	}, nil
}

func (r *RedisClient) Close() error {
	log.Info("Closing Redis connection...")
	if err := r.Client.Close(); err != nil {
		log.WithError(err).Error("Failed to close Redis connection")
		return err
	}
	log.Info("Redis connection closed")
	return nil
}
