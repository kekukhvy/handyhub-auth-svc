package logger

import (
	"bytes"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct{}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b *bytes.Buffer
	if entry.Buffer != nil {
		b = entry.Buffer
	} else {
		b = &bytes.Buffer{}
	}

	// Define colors
	var levelColor int
	switch entry.Level {
	case logrus.DebugLevel, logrus.TraceLevel:
		levelColor = 36 // Cyan
	case logrus.InfoLevel:
		levelColor = 32 // Green
	case logrus.WarnLevel:
		levelColor = 33 // Yellow
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		levelColor = 31 // Red
	default:
		levelColor = 37 // White
	}

	// Format the log entry
	timestamp := entry.Time.Format(time.RFC3339)
	fields := ""
	for k, v := range entry.Data {
		fields += fmt.Sprintf("%s=%v ", k, v)
	}
	if fields != "" {
		fields = "{" + fields[:len(fields)-1] + "} "
	}
	fmt.Fprintf(b, "\x1b[%dm[%s] [%s] %s%s\x1b[0m\n", levelColor, timestamp, entry.Level.String(), fields, entry.Message)

	return b.Bytes(), nil
}
