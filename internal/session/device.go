package session

import (
	"handyhub-auth-svc/internal/models"
	"net/http"
	"strings"
)

// ParseDeviceInfo extracts device information from User-Agent string
func ParseDeviceInfo(userAgent string) *models.DeviceInfo {
	if userAgent == "" {
		return &models.DeviceInfo{
			DeviceType: models.DeviceTypeUnknown,
			OS:         "Unknown",
			Browser:    "Unknown",
			Version:    "Unknown",
		}
	}

	userAgent = strings.ToLower(userAgent)
	deviceInfo := &models.DeviceInfo{}

	// Detect device type
	deviceInfo.DeviceType = detectDeviceType(userAgent)

	// Detect operating system
	deviceInfo.OS = detectOS(userAgent)

	// Detect browser
	deviceInfo.Browser = detectBrowser(userAgent)

	// For now, version detection is simplified
	deviceInfo.Version = "Unknown"

	return deviceInfo
}

// detectDeviceType determines the type of device from user agent
func detectDeviceType(userAgent string) string {
	if strings.Contains(userAgent, "mobile") ||
		strings.Contains(userAgent, "android") ||
		strings.Contains(userAgent, "iphone") {
		return models.DeviceTypeMobile
	}

	if strings.Contains(userAgent, "tablet") ||
		strings.Contains(userAgent, "ipad") {
		return models.DeviceTypeTablet
	}

	return models.DeviceTypeDesktop
}

// detectOS identifies the operating system from user agent
func detectOS(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "windows"):
		return "Windows"
	case strings.Contains(userAgent, "mac") || strings.Contains(userAgent, "darwin"):
		return "macOS"
	case strings.Contains(userAgent, "linux"):
		return "Linux"
	case strings.Contains(userAgent, "android"):
		return "Android"
	case strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ipad"):
		return "iOS"
	default:
		return "Unknown"
	}
}

// detectBrowser identifies the browser from user agent
func detectBrowser(userAgent string) string {
	switch {
	case strings.Contains(userAgent, "chrome") && !strings.Contains(userAgent, "edg"):
		return "Chrome"
	case strings.Contains(userAgent, "firefox"):
		return "Firefox"
	case strings.Contains(userAgent, "safari") && !strings.Contains(userAgent, "chrome"):
		return "Safari"
	case strings.Contains(userAgent, "edg"):
		return "Edge"
	case strings.Contains(userAgent, "opera"):
		return "Opera"
	default:
		return "Unknown"
	}
}

// ExtractIPAddress extracts the real IP address from HTTP request
func ExtractIPAddress(r *http.Request) string {
	// Check for forwarded IP first (for load balancers/proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check other common headers
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	if clientIP := r.Header.Get("X-Client-IP"); clientIP != "" {
		return clientIP
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if colon := strings.LastIndex(ip, ":"); colon != -1 {
		ip = ip[:colon]
	}

	return ip
}

// ExtractUserAgent extracts User-Agent header from HTTP request
func ExtractUserAgent(r *http.Request) string {
	return r.Header.Get("User-Agent")
}
