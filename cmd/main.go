package main

import (
	"handyhub-auth-svc/internal/config"
	"handyhub-auth-svc/internal/logger"
	"handyhub-auth-svc/internal/server"

	"github.com/sirupsen/logrus"
)

var log = *logrus.StandardLogger()

func main() {
	cfg := config.Load()
	logger.Init(cfg.Logs.Level, cfg.Logs.Path)

	log.Infof("Application %s is starting....", cfg.App.Name)

	srv := server.New(cfg)
	if err := srv.Start(); err != nil {
		log.WithError(err).Fatalf("Error starting server: %v", err)
	}
}
