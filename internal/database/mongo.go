package database

import (
	"context"
	"handyhub-auth-svc/internal/config"
	"time"

	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type MongoDB struct {
	Client   *mongo.Client
	Database *mongo.Database
}

var log = logrus.StandardLogger()

func NewMongoDB(cfg config.Configuration) (*MongoDB, error) {
	log.Info("Connecting to MongoDB...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.Database.Timeout)*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.Database.Url))
	if err != nil {
		log.WithError(err).Errorf("Failed to connect to MongoDB: %v", err)
		return nil, err
	}

	if err := client.Ping(ctx, nil); err != nil {
		log.WithError(err).Errorf("Failed to ping MongoDB: %v", err)
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"db":   cfg.Database.DbName,
		"host": cfg.Database.Url,
	}).Info("Connected to MongoDB")

	return &MongoDB{
		Client:   client,
		Database: client.Database(cfg.Database.DbName),
	}, nil
}

func (mdb *MongoDB) Disconnect(ctx context.Context) error {
	log.Info("Disconnecting from MongoDB...")
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return mdb.Client.Disconnect(ctx)
}
