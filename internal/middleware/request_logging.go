package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func RequestLoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		var bodyBytes []byte
		if c.Request.Body != nil {
			bodyBytes, _ = io.ReadAll(c.Request.Body)
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		responseBody := &bytes.Buffer{}
		wrappedWriter := &responseWriter{
			ResponseWriter: c.Writer,
			body:           responseBody,
		}
		c.Writer = wrappedWriter

		requestData := map[string]interface{}{
			"method":     c.Request.Method,
			"url":        c.Request.URL.Path,
			"ip":         c.ClientIP(),
			"user_agent": c.Request.UserAgent(),
			"headers":    getHeaders(c),
		}

		if len(c.Request.URL.RawQuery) > 0 {
			requestData["query_params"] = c.Request.URL.RawQuery
		}

		if len(bodyBytes) > 0 && isJSONRequest(c) {
			var jsonBody interface{}
			if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
				// Маскируем пароли
				maskedBody := maskPasswords(jsonBody)
				requestData["body"] = maskedBody
			} else {
				requestData["body"] = string(bodyBytes)
			}
		}

		c.Next()

		latency := time.Since(start)
		requestData["status"] = c.Writer.Status()
		requestData["latency"] = latency.String()

		// Add response body to logging data
		if responseBody.Len() > 0 {
			var responseJSON interface{}
			if err := json.Unmarshal(responseBody.Bytes(), &responseJSON); err == nil {
				// Mask sensitive data in response if needed
				maskedResponse := maskSensitiveResponseData(responseJSON)
				requestData["response"] = maskedResponse
			} else {
				// If not JSON, log as string (truncate if too long)
				responseStr := responseBody.String()
				if len(responseStr) > 1000 {
					responseStr = responseStr[:1000] + "... (truncated)"
				}
				requestData["response"] = responseStr
			}
		}

		logrus.WithFields(logrus.Fields{
			"request_data":       requestData,
			"enable_json_output": true,
		}).Info("HTTP Request")
	}
}

func isJSONRequest(c *gin.Context) bool {
	contentType := c.GetHeader("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func getHeaders(c *gin.Context) map[string]string {
	headers := make(map[string]string)
	excludeHeaders := map[string]bool{
		"authorization": true,
		"cookie":        true,
		"set-cookie":    true,
	}

	for name, values := range c.Request.Header {
		lowerName := strings.ToLower(name)
		if !excludeHeaders[lowerName] && len(values) > 0 {
			headers[name] = values[0]
		}
	}
	return headers
}

func maskPasswords(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			if strings.ToLower(key) == "password" {
				result[key] = "***MASKED***"
			} else {
				result[key] = maskPasswords(value)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = maskPasswords(value)
		}
		return result
	default:
		return v
	}
}

// maskSensitiveResponseData masks sensitive fields in response
func maskSensitiveResponseData(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		result := make(map[string]interface{})
		for key, value := range v {
			lowerKey := strings.ToLower(key)
			// Mask sensitive response fields
			if lowerKey == "accesstoken" || lowerKey == "refreshtoken" || lowerKey == "token" {
				if strVal, ok := value.(string); ok && len(strVal) > 10 {
					result[key] = strVal[:10] + "***MASKED***"
				} else {
					result[key] = "***MASKED***"
				}
			} else {
				result[key] = maskSensitiveResponseData(value)
			}
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, value := range v {
			result[i] = maskSensitiveResponseData(value)
		}
		return result
	default:
		return v
	}
}
