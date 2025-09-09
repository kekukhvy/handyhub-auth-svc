package server

import (
	"context"
	"errors"
	"handyhub-auth-svc/clients"
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/dependency"
	"handyhub-auth-svc/internal/session"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

var log = logrus.StandardLogger()

type Server struct {
	httpServer      *http.Server
	config          *config.Configuration
	mongodb         *clients.MongoDB
	redisClient     *clients.RedisClient
	rabbitMQ        *clients.RabbitMQ
	cleanSessionJob *session.CleanupJob
}

func New(cfg *config.Configuration) *Server {
	return &Server{
		config: cfg,
	}
}

func (s *Server) Start() error {
	if err := s.initMongoDB(); err != nil {
		return err
	}

	if err := s.initRedis(); err != nil {
		return err
	}

	if err := s.initRabbitMQ(); err != nil {
		return err
	}

	if err := s.setupHTTPServer(); err != nil {
		return err
	}

	cleanupContext := context.Background()
	s.cleanSessionJob.Start(cleanupContext)

	go func() {
		log.Infof("Auth Service starting on port %s", s.config.Server.Port)
		if err := s.httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatalf("Could not listen on %s: %v\n", s.config.Server.Port, err)
		}
	}()

	s.waitForShutdown()
	return nil
}

func (s *Server) initMongoDB() error {
	mongodb, err := clients.NewMongoDB(*s.config)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize MongoDB")
		return err
	}
	s.mongodb = mongodb
	return nil
}

func (s *Server) initRedis() error {
	log.Info("Initializing Redis connection...")
	redis, err := clients.NewRedisClient(s.config)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize Redis")
		return err
	}
	s.redisClient = redis
	return nil
}

func (s *Server) initRabbitMQ() error {
	rabbitmq, err := clients.NewRabbitMQ(&s.config.Queue.RabbitMQ)
	if err != nil {
		log.WithError(err).Fatal("Failed to initialize RabbitMQ")
		return err
	}
	s.rabbitMQ = rabbitmq
	if err := rabbitmq.SetupQueue(); err != nil {
		log.WithError(err).Fatal("Failed to setup RabbitMQ queue")
		return err
	}
	return nil
}

func (s *Server) setupHTTPServer() error {
	gin.SetMode(s.config.Server.Mode)
	router := gin.Default()

	dependencyManager := dependency.NewDependencyManager(router, s.mongodb, s.redisClient.Client, s.rabbitMQ, s.config)
	s.cleanSessionJob = session.NewCleanupJob(dependencyManager.SessionManager, dependencyManager.CacheService, s.config)

	SetupRoutes(dependencyManager)

	s.httpServer = &http.Server{
		Addr:         s.config.Server.Port,
		Handler:      router,
		ReadTimeout:  time.Duration(s.config.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(s.config.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(s.config.Server.IdleTimeout) * time.Second,
	}

	log.Info("HTTP server initialized")
	return nil
}

func (s *Server) waitForShutdown() {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	log.WithField("signal", sig).Info("Shutting down server...")

	s.Shutdown()
}

func (s *Server) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if s.cleanSessionJob != nil {
		s.cleanSessionJob.Stop()
	}

	if s.redisClient != nil {
		if err := s.redisClient.Close(); err != nil {
			log.WithError(err).Error("Error closing Redis connection")
		} else {
			log.Info("Redis connection closed")
		}
	}

	if s.rabbitMQ != nil {
		if err := s.rabbitMQ.Close(); err != nil {
			log.WithError(err).Error("Error closing RabbitMQ connection")
		} else {
			log.Info("RabbitMQ connection closed")
		}
	}

	if s.mongodb != nil {
		if err := s.mongodb.Disconnect(ctx); err != nil {
			log.WithError(err).Error("Error disconnecting MongoDB")
		} else {
			log.Info("MongoDB disconnected")
		}
	}

	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.WithError(err).Fatal("Server forced to shutdown")
	}

	log.Info("Auth service gracefully stopped")
}
