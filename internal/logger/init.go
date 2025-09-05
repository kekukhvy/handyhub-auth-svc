package logger

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
)

func Init(level, path string) {
	logrus.SetFormatter(&CustomFormatter{})

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Errorf("Failed to log to file %v, using default stderr %v", path, err)
	}

	multiWriter := io.MultiWriter(os.Stdout, file)
	logrus.SetOutput(multiWriter)
	logrus.SetLevel(getLogLevel(level))
}

func getLogLevel(level string) logrus.Level {
	switch level {
	case "info":
		return logrus.InfoLevel
	case "debug":
		return logrus.DebugLevel
	case "warn":
		return logrus.WarnLevel
	case "error":
		return logrus.ErrorLevel
	case "fatal":
		return logrus.FatalLevel
	case "panic":
		return logrus.PanicLevel
	default:
		return logrus.InfoLevel
	}
}
