package config

import (
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type Configuration struct {
	Database     Database          `mapstructure:"database"`
	Redis        Redis             `mapstructure:"redis"`
	Server       ServerSettings    `mapstructure:"server"`
	App          Application       `mapstructure:"app"`
	Logs         LogsSettings      `mapstructure:"logs"`
	Security     SecuritySettings  `mapstructure:"security"`
	RateLimit    RateLimitSettings `mapstructure:"rate-limit"`
	EmailService EmailService      `mapstructure:"email-service"`
	Cache        CacheConfig       `mapstructure:"cache"`
	Queue        QueueConfig       `mapstructure:"queue"`
	Frontend     FrontendConfig    `mapstructure:"frontend"`
}

type Database struct {
	Url               string `mapstructure:"url"`
	DbName            string `mapstructure:"dbname"`
	UserCollection    string `mapstructure:"user-collection"`
	SessionCollection string `mapstructure:"session-collection"`
	Timeout           int    `mapstructure:"timeout"`
}

type Redis struct {
	Url      string `mapstructure:"url"`
	Password string `mapstructure:"password"`
	Db       int    `mapstructure:"db"`
}

type ServerSettings struct {
	Port         string `mapstructure:"port"`
	Mode         string `mapstructure:"mode"`
	ReadTimeout  int    `mapstructure:"read-timeout"`
	WriteTimeout int    `mapstructure:"write-timeout"`
	IdleTimeout  int    `mapstructure:"idle-timeout"`
}

type Application struct {
	Name     string `mapstructure:"name"`
	Timeout  int    `mapstructure:"timeout"`
	Version  string `mapstructure:"version"`
	HostLink string `mapstructure:"host-link"`
}

type LogsSettings struct {
	Level            string `mapstructure:"level"`
	Path             string `mapstructure:"log-path"`
	EnableJSONOutput bool   `mapstructure:"enable-json-output"`
}

type SecuritySettings struct {
	JwtKey                   string             `mapstructure:"jwt-key"`
	AccessTokenExpiration    int                `mapstructure:"access-token-expiration"`
	RefreshTokenExpiration   int                `mapstructure:"refresh-token-expiration"`
	PasswordSaltRounds       int                `mapstructure:"password-salt-rounds"`
	PasswordValidation       PasswordValidation `mapstructure:"password-validation"`
	LoginRateLimit           int                `mapstructure:"login-rate-limit"`
	SessionInactivityTimeout int                `mapstructure:"session-inactivity-timeout"`
	SessionCleanupInterval   int                `mapstructure:"session-cleanup-interval"`
	SessionCleanupBatchSize  int                `mapstructure:"session-cleanup-batch-size"`
}

type PasswordValidation struct {
	MinLength          int  `mapstructure:"min-length"`
	RequireUpper       bool `mapstructure:"require-upper"`
	RequireLower       bool `mapstructure:"require-lower"`
	RequireDigit       bool `mapstructure:"require-digit"`
	RequireSpecial     bool `mapstructure:"require-special"`
	MaxCharRepeats     int  `mapstructure:"max-char-repeats"`
	MaxSequentialChars int  `mapstructure:"max-sequential-chars"`
}
type RateLimitSettings struct {
	LoginAttempts int `mapstructure:"login-attempts"`
	WindowMinutes int `mapstructure:"window-minutes"`
}

type EmailService struct {
	Enabled     bool   `mapstructure:"enabled"`
	Url         string `mapstructure:"url"`
	FrontendURL string `mapstructure:"frontend-url"`
	DefaultFrom string `mapstructure:"default-from"`
}
type CacheConfig struct {
	ExpirationMinutes         int `mapstructure:"expiration-minutes"`
	ExtendedExpirationMinutes int `mapstructure:"extended-expiration-minutes"`
	SessionExpirationMinutes  int `mapstructure:"session-expiration-minutes"`
}

type QueueConfig struct {
	RabbitMQ RabbitMQConfig `mapstructure:"rabbitmq"`
}

type RabbitMQConfig struct {
	Url            string `mapstructure:"url"`
	Exchange       string `mapstructure:"exchange"`
	ExchangeType   string `mapstructure:"exchange-type"`
	EmailQueue     string `mapstructure:"email-queue"`
	PrefetchCount  int    `mapstructure:"prefetch-count"`
	ReconnectDelay int    `mapstructure:"reconnect-delay"`
	Timeout        int    `mapstructure:"timeout"`
	RoutingKey     string `mapstructure:"routing-key"`
	PrefetchSize   int    `mapstructure:"prefetch-size"`
	Global         bool   `mapstructure:"global"`
	Durable        bool   `mapstructure:"durable"`
	AutoDelete     bool   `mapstructure:"auto-delete"`
	Internal       bool   `mapstructure:"internal"`
	NoWait         bool   `mapstructure:"no-wait"`
	Exclusive      bool   `mapstructure:"exclusive"`
	AutoAck        bool   `mapstructure:"auto-ack"`
	NoLocal        bool   `mapstructure:"no-local"`
	Consumer       string `mapstructure:"consumer"`
}

type FrontendConfig struct {
	Url       string `mapstructure:"url"`
	LoginPath string `mapstructure:"login-path"`
}

func Load() *Configuration {
	cfg := read()
	logrus.Info("Configuration loaded")

	// Override with environment variables
	mongoUri := os.Getenv("MONGODB_URL")
	if mongoUri != "" {
		cfg.Database.Url = mongoUri
	}

	dbName := os.Getenv("DB_NAME")
	if dbName != "" {
		cfg.Database.DbName = dbName
	}

	redisUrl := os.Getenv("REDIS_URL")
	if redisUrl != "" {
		cfg.Redis.Url = redisUrl
	}

	redisDB := os.Getenv("REDIS_DB")
	if redisDB != "" {
		if db, err := strconv.Atoi(redisDB); err == nil {
			cfg.Redis.Db = db
		}
	}

	rabbitmqUrl := os.Getenv("RABBITMQ_URL")
	if rabbitmqUrl != "" {
		cfg.Queue.RabbitMQ.Url = rabbitmqUrl
	}

	jwtKey := os.Getenv("JWT_KEY")
	if jwtKey != "" {
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
