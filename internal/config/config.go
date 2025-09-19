package config

import (
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Configuration struct {
	App              Application      `mapstructure:"app"`
	Logs             LogsSettings     `mapstructure:"logs"`
	Server           ServerSettings   `mapstructure:"server"`
	Database         Database         `mapstructure:"database"`
	Redis            Redis            `mapstructure:"redis"`
	Messaging        MessagingConfig  `mapstructure:"messaging"`
	Security         SecuritySettings `mapstructure:"security"`
	Cache            CacheConfig      `mapstructure:"cache"`
	ExternalServices ExternalServices `mapstructure:"external-services"`
}

type Application struct {
	Name     string `mapstructure:"name"`
	Version  string `mapstructure:"version"`
	Timeout  int    `mapstructure:"timeout"`
	HostLink string `mapstructure:"host-link"`
}

type LogsSettings struct {
	Level            string `mapstructure:"level"`
	Path             string `mapstructure:"path"`
	EnableJSONOutput bool   `mapstructure:"enable-json-output"`
}

type ServerSettings struct {
	Port         string `mapstructure:"port"`
	Mode         string `mapstructure:"mode"`
	ReadTimeout  int    `mapstructure:"read-timeout"`
	WriteTimeout int    `mapstructure:"write-timeout"`
	IdleTimeout  int    `mapstructure:"idle-timeout"`
}

type Database struct {
	Url         string              `mapstructure:"url"`
	DbName      string              `mapstructure:"dbname"`
	Timeout     int                 `mapstructure:"timeout"`
	Collections DatabaseCollections `mapstructure:"collections"`
}

type DatabaseCollections struct {
	Users    string `mapstructure:"users"`
	Sessions string `mapstructure:"sessions"`
}

type Redis struct {
	Url      string `mapstructure:"url"`
	Password string `mapstructure:"password"`
	Db       int    `mapstructure:"db"`
}

type MessagingConfig struct {
	RabbitMQ RabbitMQConfig `mapstructure:"rabbitmq"`
	Queues   QueuesConfig   `mapstructure:"queues"`
}

type RabbitMQConfig struct {
	Url            string `mapstructure:"url"`
	Exchange       string `mapstructure:"exchange"`
	ExchangeType   string `mapstructure:"exchange-type"`
	PrefetchCount  int    `mapstructure:"prefetch-count"`
	PrefetchSize   int    `mapstructure:"prefetch-size"`
	Global         bool   `mapstructure:"global"`
	ReconnectDelay int    `mapstructure:"reconnect-delay"`
	Timeout        int    `mapstructure:"timeout"`
	Durable        bool   `mapstructure:"durable"`
	AutoDelete     bool   `mapstructure:"auto-delete"`
	Internal       bool   `mapstructure:"internal"`
	NoWait         bool   `mapstructure:"no-wait"`
	Exclusive      bool   `mapstructure:"exclusive"`
	AutoAck        bool   `mapstructure:"auto-ack"`
	NoLocal        bool   `mapstructure:"no-local"`
}

type QueuesConfig struct {
	Email        QueueConfig `mapstructure:"email"`
	UserActivity QueueConfig `mapstructure:"user-activity"`
}

type QueueConfig struct {
	Name       string `mapstructure:"name"`
	RoutingKey string `mapstructure:"routing-key"`
	Consumer   string `mapstructure:"consumer"`
}

type SecuritySettings struct {
	JwtKey       string         `mapstructure:"jwt-key"`
	Tokens       TokensConfig   `mapstructure:"tokens"`
	Password     PasswordConfig `mapstructure:"password"`
	Session      SessionConfig  `mapstructure:"session"`
	RateLimiting RateLimiting   `mapstructure:"rate-limiting"`
}

type RateLimiting struct {
	RequestsPerMinute int `mapstructure:"requests-per-minute"`
	BurstSize         int `mapstructure:"burst-size"`
	LoginAttempts     int `mapstructure:"login-attempts"`
	WindowMinutes     int `mapstructure:"window-minutes"`
}

type TokensConfig struct {
	AccessExpiration  int `mapstructure:"access-expiration"`
	RefreshExpiration int `mapstructure:"refresh-expiration"`
}

type PasswordConfig struct {
	SaltRounds int                `mapstructure:"salt-rounds"`
	Validation PasswordValidation `mapstructure:"validation"`
}

type PasswordValidation struct {
	MinLength          int  `mapstructure:"min-length"`
	RequireUppercase   bool `mapstructure:"require-uppercase"`
	RequireLowercase   bool `mapstructure:"require-lowercase"`
	RequireNumber      bool `mapstructure:"require-number"`
	RequireSpecial     bool `mapstructure:"require-special"`
	MaxCharRepeats     int  `mapstructure:"max-char-repeats"`
	MaxSequentialChars int  `mapstructure:"max-sequential-chars"`
}

type SessionConfig struct {
	InactivityTimeout int `mapstructure:"inactivity-timeout"`
	CleanupInterval   int `mapstructure:"cleanup-interval"`
	CleanupBatchSize  int `mapstructure:"cleanup-batch-size"`
}

type CacheConfig struct {
	ExpirationMinutes         int `mapstructure:"expiration-minutes"`
	SessionExpirationMinutes  int `mapstructure:"session-expiration-minutes"`
	ExtendedExpirationMinutes int `mapstructure:"extended-expiration-minutes"`
}

type ExternalServices struct {
	EmailService EmailServiceConfig `mapstructure:"email-service"`
	Frontend     FrontendConfig     `mapstructure:"frontend"`
}

type EmailServiceConfig struct {
	Enabled     bool   `mapstructure:"enabled"`
	Url         string `mapstructure:"url"`
	FrontendURL string `mapstructure:"frontend-url"`
}

type FrontendConfig struct {
	Url       string `mapstructure:"url"`
	LoginPath string `mapstructure:"login-path"`
}

func Load() *Configuration {
	cfg := read()
	logrus.Info("Configuration loaded")

	// Override with environment variables
	if mongoUri := os.Getenv("MONGODB_URL"); mongoUri != "" {
		cfg.Database.Url = mongoUri
	}

	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		cfg.Database.DbName = dbName
	}

	if redisUrl := os.Getenv("REDIS_URL"); redisUrl != "" {
		cfg.Redis.Url = redisUrl
	}

	if redisDB := os.Getenv("REDIS_DB"); redisDB != "" {
		if db, err := strconv.Atoi(redisDB); err == nil {
			cfg.Redis.Db = db
		}
	}

	if rabbitmqUrl := os.Getenv("RABBITMQ_URL"); rabbitmqUrl != "" {
		cfg.Messaging.RabbitMQ.Url = rabbitmqUrl
	}

	if jwtKey := os.Getenv("JWT_KEY"); jwtKey != "" {
		cfg.Security.JwtKey = jwtKey
	}

	return cfg
}

func read() *Configuration {
	viper.SetConfigFile("internal/config/cfg.yml")
	viper.AutomaticEnv()
	viper.SetConfigType("yml")

	var config Configuration

	err := viper.ReadInConfig()
	if err != nil {
		logrus.Panic("Error reading config file, %s", err)
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		logrus.Panic("Error unmarshalling config file, %s", err)
	}

	return &config
}
