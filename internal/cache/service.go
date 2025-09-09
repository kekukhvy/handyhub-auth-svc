package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

type Service interface {
	CacheUser(ctx context.Context, user *models.User, duration int) error
	CheckRateLimit(ctx context.Context, key string, limit int) (bool, error)
	IncrementRateLimit(ctx context.Context, key string, window int) error
	ResetFailedLoginAttempts(ctx context.Context, key string) error
	CacheActiveSession(ctx context.Context, session *models.Session) error
	InvalidateUserSessions(ctx context.Context, userID string) error
	GetActiveSession(ctx context.Context, key string) (*models.ActiveSession, error)
	UpdateSessionActivity(ctx context.Context, key string) error
}

var log = logrus.StandardLogger()

type cacheService struct {
	client *redis.Client
	cfg    *config.CacheConfig
}

func NewCacheService(client *redis.Client, cfg *config.Configuration) Service {
	return &cacheService{
		client: client,
		cfg:    &cfg.Cache}
}

func (c *cacheService) CacheUser(ctx context.Context, user *models.User, duration int) error {
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

func (c *cacheService) CheckRateLimit(ctx context.Context, key string, limit int) (bool, error) {
	rateLimitKey := fmt.Sprintf("rate_limit:%s", key)

	current, err := c.client.Get(ctx, rateLimitKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil // No previous attempts
		}
		log.WithError(err).WithField("key", key).Error("Failed to check rate limit")
		return false, models.ErrRedisGet
	}

	count, err := strconv.Atoi(current)
	if err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to parse rate limit count")
		return false, models.ErrRedisGet
	}

	return count >= limit, nil
}

func (c *cacheService) IncrementRateLimit(ctx context.Context, key string, window int) error {
	rateLimitKey := fmt.Sprintf("rate_limit:%s", key)

	pipe := c.client.TxPipeline()
	pipe.Incr(ctx, rateLimitKey)
	pipe.Expire(ctx, rateLimitKey, time.Duration(window)*time.Second)

	_, err := pipe.Exec(ctx)
	if err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to increment rate limit")
		return models.ErrRedisSet
	}

	return nil
}

func (c *cacheService) ResetFailedLoginAttempts(ctx context.Context, key string) error {
	rateLimitKey := fmt.Sprintf("rate_limit:%s", key)

	err := c.client.Del(ctx, rateLimitKey).Err()
	if err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to reset failed login attempts")
		return models.ErrRedisDelete
	}

	return nil
}

func (c *cacheService) CacheActiveSession(ctx context.Context, session *models.Session) error {
	key := fmt.Sprintf("session:%s:%s", session.UserID.Hex(), session.SessionID)
	activeSession := session.ToActiveSession()

	data, err := json.Marshal(activeSession)
	if err != nil {
		log.WithError(err).WithField("session_id", session.SessionID).Error("Failed to marshal session for cache")
		return models.ErrRedisSet
	}

	expiration := time.Until(session.ExpiresAt)
	if expiration <= 0 {
		log.WithField("session_id", session.SessionID).Warn("Session already expired, not caching")
		return nil
	}

	err = c.client.Set(ctx, key, data, expiration).Err()
	if err != nil {
		log.WithError(err).WithField("session_id", session.SessionID).Error("Failed to cache session")
		return models.ErrRedisSet
	}

	log.WithField("session_id", session.SessionID).Debug("Session cached successfully")
	return nil
}

func (c *cacheService) InvalidateUserSessions(ctx context.Context, userID string) error {
	log.WithField("user_id", userID).Debug("Invalidating all user sessions from cache")

	pattern := fmt.Sprintf("session:%s:*", userID)

	keys, err := c.client.Keys(ctx, pattern).Result()
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to get user session keys")
		return models.ErrRedisGet
	}

	if len(keys) == 0 {
		log.WithField("user_id", userID).Debug("No sessions found in cache for user")
		return nil
	}

	deleted, err := c.client.Del(ctx, keys...).Result()
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to delete user sessions")
		return models.ErrRedisDelete
	}

	log.WithFields(logrus.Fields{
		"user_id": userID,
		"deleted": deleted,
	}).Info("User sessions invalidated from cache")

	return nil
}

func (c *cacheService) GetActiveSession(ctx context.Context, key string) (*models.ActiveSession, error) {
	log.WithField("key", key).Debug("Getting active session from cache")

	data, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			log.WithField("key", key).Debug("Session not found in cache")
			return nil, nil // Not an error, just not found
		}
		log.WithError(err).WithField("key", key).Error("Failed to get session from cache")
		return nil, models.ErrRedisGet
	}

	var session models.ActiveSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to unmarshal session from cache")
		return nil, models.ErrRedisGet
	}

	log.WithField("key", key).Debug("Session retrieved from cache successfully")
	return &session, nil
}

func (c *cacheService) UpdateSessionActivity(ctx context.Context, key string) error {
	log.WithField("key", key).Debug("Updating session activity in cache")

	// Get current session
	session, err := c.GetActiveSession(ctx, key)
	if err != nil || session == nil {
		return err
	}

	// Update last active time
	session.LastActiveAt = time.Now()

	// Re-cache with updated time and extended TTL
	data, err := json.Marshal(session)
	if err != nil {
		log.WithError(err).Error("Failed to marshal session for activity update")
		return models.ErrRedisSet
	}

	extendedTTL := time.Duration(c.cfg.ExtendedExpirationMinutes) * time.Minute
	err = c.client.Set(ctx, key, data, extendedTTL).Err()
	if err != nil {
		log.WithError(err).WithField("key", key).Error("Failed to update session activity")
		return models.ErrRedisSet
	}

	log.WithField("key", key).Debug("Session activity updated successfully")
	return nil
}
