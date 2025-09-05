package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	EnableJSONOutput bool
}

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

	// Обрабатываем обычные поля (исключая специальные)
	fields := ""
	var contextID string
	var requestData interface{}
	var shouldOutputJSON bool

	for k, v := range entry.Data {
		if k == "email" {
			contextID = fmt.Sprintf("%v", v)
		} else if k == "request_data" {
			requestData = v
		} else if k == "enable_json_output" {
			if enabled, ok := v.(bool); ok {
				shouldOutputJSON = enabled && f.EnableJSONOutput
			}
		} else {
			fields += fmt.Sprintf("%s=%v ", k, v)
		}
	}

	// Формируем строку с context_id если есть
	contextPart := ""
	if contextID != "" {
		contextPart = fmt.Sprintf(" [%s]", contextID)
	}

	// Основное лог сообщение
	fmt.Fprintf(b, "\x1b[%dm[%s] [%s]%s %s\x1b[0m\n",
		levelColor, timestamp, entry.Level.String(), contextPart, entry.Message)

	// Добавляем остальные поля на следующей строке если они есть
	if fields != "" {
		fmt.Fprintf(b, "\x1b[%dm       {%s}\x1b[0m\n", levelColor, fields[:len(fields)-1])
	}

	// Добавляем JSON на следующей строке если нужно
	if shouldOutputJSON && requestData != nil {
		jsonBytes, err := json.MarshalIndent(requestData, "", "  ")
		if err == nil {
			// Добавляем цвет для JSON (светло-серый)
			fmt.Fprintf(b, "\x1b[37m%s\x1b[0m\n", string(jsonBytes))
		}
	}

	return b.Bytes(), nil
}
