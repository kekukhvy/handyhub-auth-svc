package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type Service interface {
	CacheUser(ctx context.Context, user *models.User, duration int) error
}

var log = logrus.StandardLogger()

type cacheService struct {
	client *redis.Client
}

func NewCacheService(client *redis.Client) Service {
	return &cacheService{client: client}
}

func (c cacheService) CacheUser(ctx context.Context, user *models.User, duration int) error {
	log.WithField("email", user.Email).Debug("Caching user profile")
	key := fmt.Sprintf("user:%s", user.ID.Hex())

	// Store user profile (without password)
	userProfile := user.ToProfile()
	data, err := json.Marshal(userProfile)
	if err != nil {
		log.WithError(err).WithField("user_id", user.ID.Hex()).Error("Failed to marshal user for cache")
		return models.ErrRedisSet
	}

	expiration := time.Duration(duration) * time.Minute
	err = c.client.Set(ctx, key, data, expiration).Err()
	if err != nil {
		log.WithError(err).WithField("user_id", userProfile.ID.Hex()).Error("Failed to cache user profile")
		return models.ErrRedisSet
	}

	log.WithField("email", userProfile.Email).Debug("User profile cached successfully")
	return nil
}
