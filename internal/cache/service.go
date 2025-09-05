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
	CacheUserProfile(ctx context.Context, profile *models.UserProfile, duration int) error
}

var log = logrus.StandardLogger()

type cacheService struct {
	client *redis.Client
}

func NewCacheService(client *redis.Client) Service {
	return &cacheService{client: client}
}

func (c cacheService) CacheUserProfile(ctx context.Context, profile *models.UserProfile, duration int) error {
	key := fmt.Sprintf("user:%s", profile.ID.Hex())

	data, err := json.Marshal(profile)
	if err != nil {
		log.WithError(err).WithField("user_id", profile.ID.Hex()).Error("Failed to marshal user profile for cache")
		return models.ErrRedisSet
	}

	expiration := time.Duration(duration) * time.Minute
	err = c.client.Set(ctx, key, data, expiration).Err()
	if err != nil {
		log.WithError(err).WithField("user_id", profile.ID.Hex()).Error("Failed to cache user profile")
		return models.ErrRedisSet
	}

	log.WithField("user_id", profile.ID.Hex()).Debug("User profile cached successfully")
	return nil
}
