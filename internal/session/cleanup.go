package session

import (
	"context"
	"fmt"
	"handyhub-auth-svc/internal/cache"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/sirupsen/logrus"
)

type CleanupJob struct {
	manager           Manager
	cacheService      cache.Service
	filters           *Filters
	interval          time.Duration
	inactivityTimeout time.Duration
	batchSize         int
	stopChan          chan struct{}
}

func NewCleanupJob(manager Manager, cache cache.Service, cfg *config.Configuration) *CleanupJob {
	// Default cleanup interval
	interval := 10 * time.Minute
	if cfg.Security.SessionCleanupInterval > 0 {
		interval = time.Duration(cfg.Security.SessionCleanupInterval) * time.Minute
	}

	// Inactivity timeout
	inactivityTimeout := 30 * time.Minute
	if cfg.Security.SessionInactivityTimeout > 0 {
		inactivityTimeout = time.Duration(cfg.Security.SessionInactivityTimeout) * time.Minute
	}

	// Batch size
	batchSize := 100
	if cfg.Security.SessionCleanupBatchSize > 0 {
		batchSize = cfg.Security.SessionCleanupBatchSize
	}

	return &CleanupJob{
		manager:           manager,
		cacheService:      cache,
		filters:           NewFilters(),
		interval:          interval,
		inactivityTimeout: inactivityTimeout,
		batchSize:         batchSize,
		stopChan:          make(chan struct{}),
	}
}

func (j *CleanupJob) Start(ctx context.Context) {
	log.WithFields(logrus.Fields{
		"interval":   j.interval,
		"timeout":    j.inactivityTimeout,
		"batch_size": j.batchSize,
	}).Info("Starting session cleanup job")

	go j.run(ctx)
}

func (j *CleanupJob) Stop() {
	log.Info("Stopping session cleanup job")
	close(j.stopChan)
}

func (j *CleanupJob) run(ctx context.Context) {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Session cleanup job stopped due to context cancellation")
			return
		case <-j.stopChan:
			log.Info("Session cleanup job stopped")
			return
		case <-ticker.C:
			if err := j.cleanup(ctx); err != nil {
				log.WithError(err).Error("Session cleanup failed")
			}
		}
	}
}

func (j *CleanupJob) cleanup(ctx context.Context) error {
	startTime := time.Now()
	log.Debug("Starting session cleanup cycle")

	// Get all active sessions from MongoDB
	activeSessions, err := j.manager.GetActiveSessions(ctx, j.batchSize)
	if err != nil {
		return fmt.Errorf("failed to get active sessions: %w", err)
	}

	if len(activeSessions) == 0 {
		log.Debug("No active sessions found")
		return nil
	}

	log.WithField("sessions_count", len(activeSessions)).Debug("Found active sessions to check")

	var (
		expiredCount    = 0
		updatedCount    = 0
		errorCount      = 0
		restoredToRedis = 0
	)

	// Process sessions in batches
	for _, session := range activeSessions {
		if err := j.processSession(ctx, session, &expiredCount, &updatedCount, &errorCount, &restoredToRedis); err != nil {
			log.WithError(err).WithField("session_id", session.SessionID).Error("Failed to process session")
			errorCount++
		}
	}

	duration := time.Since(startTime)
	log.WithFields(logrus.Fields{
		"duration":          duration,
		"total_sessions":    len(activeSessions),
		"expired_sessions":  expiredCount,
		"updated_sessions":  updatedCount,
		"restored_to_redis": restoredToRedis,
		"errors":            errorCount,
	}).Info("Session cleanup cycle completed")

	return nil
}

func (j *CleanupJob) processSession(ctx context.Context, session *models.Session, expiredCount, updatedCount, errorCount, restoredCount *int) error {
	sessionKey := fmt.Sprintf("session:%s:%s", session.UserID.Hex(), session.SessionID)

	// Check if session exists in Redis
	activeSession, err := j.cacheService.GetActiveSession(ctx, sessionKey)
	if err != nil {
		log.WithError(err).WithField("session_id", session.SessionID).Warn("Failed to check session in Redis")
		// Continue processing even if Redis check fails
	}

	// If session exists in Redis, it's actively used
	if activeSession != nil {
		log.WithField("session_id", session.SessionID).Debug("Session found in Redis, skipping")
		return nil
	}

	// Session not in Redis - check if it should be expired due to inactivity
	timeSinceLastActivity := time.Since(session.LastActiveAt)

	if timeSinceLastActivity > j.inactivityTimeout {
		// Session expired due to inactivity
		log.WithFields(logrus.Fields{
			"session_id":    session.SessionID,
			"user_id":       session.UserID.Hex(),
			"last_activity": session.LastActiveAt,
			"inactive_for":  timeSinceLastActivity,
		}).Info("Marking session as expired due to inactivity")

		// Mark session as inactive
		if err := j.markSessionAsExpired(ctx, session); err != nil {
			return fmt.Errorf("failed to mark session as expired: %w", err)
		}

		*expiredCount++
		*updatedCount++
	} else {
		// Session is within activity window but missing from Redis
		// This could happen after Redis restart - restore it
		log.WithFields(logrus.Fields{
			"session_id":    session.SessionID,
			"last_activity": session.LastActiveAt,
			"inactive_for":  timeSinceLastActivity,
		}).Debug("Session within activity window but missing from Redis, restoring")

		if err := j.cacheService.CacheActiveSession(ctx, session); err != nil {
			log.WithError(err).WithField("session_id", session.SessionID).Warn("Failed to restore session to Redis")
			// Don't return error, continue with other sessions
		} else {
			*restoredCount++
		}
	}

	return nil
}

func (j *CleanupJob) markSessionAsExpired(ctx context.Context, session *models.Session) error {
	session.IsActive = false
	return j.manager.Update(ctx, session)
}
