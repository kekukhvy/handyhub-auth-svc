package session

import (
	"handyhub-auth-svc/internal/models"
	"time"

	"github.com/sirupsen/logrus"
)

// SecurityAnalyzer analyzes session security and risk factors
type SecurityAnalyzer struct{}

// NewSecurityAnalyzer creates a new security analyzer instance
func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{}
}

// SecurityInfo provides comprehensive security information about a session
type SecurityInfo struct {
	IsNewDevice       bool     `json:"isNewDevice"`
	IsNewLocation     bool     `json:"isNewLocation"`
	RiskScore         int      `json:"riskScore"` // 0-100, higher = more risky
	SuspiciousSignins int      `json:"suspiciousSignins"`
	LastKnownIP       string   `json:"lastKnownIP"`
	IPChanged         bool     `json:"ipChanged"`
	DeviceChanged     bool     `json:"deviceChanged"`
	Recommendations   []string `json:"recommendations"`
}

// AnalyzeSecurity performs comprehensive security analysis of a session

func (sa *SecurityAnalyzer) AnalyzeSecurity(currentSession *models.Session, previousSessions []*models.Session) *SecurityInfo {
	info := &SecurityInfo{
		RiskScore:       0,
		Recommendations: []string{},
	}

	if len(previousSessions) == 0 {
		return sa.analyzeFirstTimeLogin(info, currentSession)
	}

	sa.analyzeDeviceChanges(info, currentSession, previousSessions)
	sa.analyzeLocationChanges(info, currentSession, previousSessions)
	sa.analyzeSuspiciousPatterns(info, currentSession, previousSessions)
	sa.generateRecommendations(info)

	sa.logSecurityAnalysis(currentSession, info)
	return info
}

// analyzeFirstTimeLogin handles analysis for first-time logins
func (sa *SecurityAnalyzer) analyzeFirstTimeLogin(info *SecurityInfo, session *models.Session) *SecurityInfo {
	info.IsNewDevice = true
	info.IsNewLocation = true
	info.RiskScore = 25

	info.Recommendations = append(info.Recommendations, "Enable two-factor authentication")
	info.Recommendations = append(info.Recommendations, "Verify email address")

	var deviceType string
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	} else {
		deviceType = "unknown"
	}

	log.WithFields(logrus.Fields{
		"session_id":  session.SessionID,
		"user_id":     session.UserID.Hex(),
		"risk_score":  info.RiskScore,
		"device_type": deviceType,
		"ip_address":  session.IPAddress,
	}).Info("First-time login security analysis completed")

	return info
}

// analyzeDeviceChanges detects and analyzes device changes
func (sa *SecurityAnalyzer) analyzeDeviceChanges(info *SecurityInfo, current *models.Session, previous []*models.Session) {
	currentDevice := current.DeviceInfo
	deviceFound := false

	for _, prev := range previous {
		if sa.isSameDevice(currentDevice, prev.DeviceInfo) {
			deviceFound = true
			break
		}
	}

	if !deviceFound {
		info.IsNewDevice = true
		info.DeviceChanged = true
		info.RiskScore += 30
		info.Recommendations = append(info.Recommendations, "Verify this new device login")

		sa.logDeviceChange(current, currentDevice)
	}
}

func (sa *SecurityAnalyzer) logDeviceChange(session *models.Session, deviceInfo *models.DeviceInfo) {
	deviceType := "unknown"
	os := "unknown"
	browser := "unknown"

	if deviceInfo != nil {
		deviceType = deviceInfo.DeviceType
		os = deviceInfo.OS
		browser = deviceInfo.Browser
	}

	log.WithFields(logrus.Fields{
		"session_id":   session.SessionID,
		"user_id":      session.UserID.Hex(),
		"new_device":   true,
		"device_type":  deviceType,
		"os":           os,
		"browser":      browser,
		"ip_address":   session.IPAddress,
		"last_service": session.LastService,
		"last_action":  session.LastAction,
	}).Info("New device detected in security analysis")
}

// analyzeLocationChanges detects and analyzes location/IP changes
func (sa *SecurityAnalyzer) analyzeLocationChanges(info *SecurityInfo, current *models.Session, previous []*models.Session) {
	if len(previous) > 0 {
		lastSession := sa.getMostRecentSession(previous)
		info.LastKnownIP = lastSession.IPAddress

		if current.IPAddress != lastSession.IPAddress {
			info.IPChanged = true
			info.IsNewLocation = true
			info.RiskScore += 20
			info.Recommendations = append(info.Recommendations, "Unusual location detected")

			sa.logLocationChange(current, lastSession)
		}
	}
}

func (sa *SecurityAnalyzer) logLocationChange(current *models.Session, lastSession *models.Session) {
	log.WithFields(logrus.Fields{
		"session_id":      current.SessionID,
		"user_id":         current.UserID.Hex(),
		"location_change": true,
		"old_ip":          lastSession.IPAddress,
		"new_ip":          current.IPAddress,
		"time_diff":       current.CreatedAt.Sub(lastSession.CreatedAt),
		"last_service":    current.LastService,
		"last_action":     current.LastAction,
	}).Info("Location change detected in security analysis")
}

// analyzeSuspiciousPatterns looks for suspicious login patterns
func (sa *SecurityAnalyzer) analyzeSuspiciousPatterns(info *SecurityInfo, current *models.Session, previous []*models.Session) {
	// Count IP changes in recent sessions
	ipChanges := 0
	deviceChanges := 0
	recentThreshold := time.Now().AddDate(0, 0, -7) // Last 7 days

	for _, prev := range previous {
		if prev.CreatedAt.After(recentThreshold) {
			if prev.IPAddress != current.IPAddress {
				ipChanges++
			}
			if !sa.isSameDevice(current.DeviceInfo, prev.DeviceInfo) {
				deviceChanges++
			}
		}
	}

	info.SuspiciousSignins = ipChanges

	// High frequency of IP changes
	if ipChanges > 3 {
		info.RiskScore += 25
		info.Recommendations = append(info.Recommendations, "Multiple IP addresses detected")
	}

	// High frequency of device changes
	if deviceChanges > 2 {
		info.RiskScore += 20
		info.Recommendations = append(info.Recommendations, "Multiple devices detected")
	}

	// Rapid successive logins
	if len(previous) > 0 {
		lastLogin := sa.getMostRecentSession(previous)
		timeSinceLastLogin := current.CreatedAt.Sub(lastLogin.CreatedAt)

		if timeSinceLastLogin < 5*time.Minute {
			info.RiskScore += 15
			info.Recommendations = append(info.Recommendations, "Rapid successive logins detected")
		}
	}
}

// generateRecommendations provides security recommendations based on analysis
func (sa *SecurityAnalyzer) generateRecommendations(info *SecurityInfo) {
	if info.RiskScore > 70 {
		info.Recommendations = append(info.Recommendations, "High risk login - consider additional verification")
	} else if info.RiskScore > 40 {
		info.Recommendations = append(info.Recommendations, "Moderate risk login - review account activity")
	}

	if info.IsNewDevice {
		info.Recommendations = append(info.Recommendations, "Remember this device for future logins")
	}

	if info.RiskScore > 50 {
		info.Recommendations = append(info.Recommendations, "Change password if you suspect unauthorized access")
	}
}

// isSameDevice compares two device info objects to determine if they're the same device
func (sa *SecurityAnalyzer) isSameDevice(device1, device2 *models.DeviceInfo) bool {
	if device1 == nil || device2 == nil {
		return false
	}

	return device1.DeviceType == device2.DeviceType &&
		device1.OS == device2.OS &&
		device1.Browser == device2.Browser
}

// getMostRecentSession returns the most recently created session
func (sa *SecurityAnalyzer) getMostRecentSession(sessions []*models.Session) *models.Session {
	if len(sessions) == 0 {
		return nil
	}

	mostRecent := sessions[0]
	for _, session := range sessions[1:] {
		if session.CreatedAt.After(mostRecent.CreatedAt) {
			mostRecent = session
		}
	}
	return mostRecent
}

// GetRiskLevel returns a human-readable risk level
func (sa *SecurityAnalyzer) GetRiskLevel(riskScore int) string {
	switch {
	case riskScore >= 80:
		return "Very High"
	case riskScore >= 60:
		return "High"
	case riskScore >= 40:
		return "Medium"
	case riskScore >= 20:
		return "Low"
	default:
		return "Very Low"
	}
}

// ShouldRequireAdditionalVerification determines if additional verification is needed
func (sa *SecurityAnalyzer) ShouldRequireAdditionalVerification(riskScore int) bool {
	return riskScore >= 60
}

// ShouldNotifyUser determines if user should be notified about this login
func (sa *SecurityAnalyzer) ShouldNotifyUser(info *SecurityInfo) bool {
	return info.IsNewDevice || info.IsNewLocation || info.RiskScore >= 40
}

func (sa *SecurityAnalyzer) logSecurityAnalysis(session *models.Session, info *SecurityInfo) {
	deviceType := "unknown"
	if session.DeviceInfo != nil {
		deviceType = session.DeviceInfo.DeviceType
	}

	log.WithFields(logrus.Fields{
		"session_id":         session.SessionID,
		"user_id":            session.UserID.Hex(),
		"risk_score":         info.RiskScore,
		"risk_level":         sa.GetRiskLevel(info.RiskScore),
		"is_new_device":      info.IsNewDevice,
		"is_new_location":    info.IsNewLocation,
		"ip_changed":         info.IPChanged,
		"device_changed":     info.DeviceChanged,
		"suspicious_signins": info.SuspiciousSignins,
		"device_type":        deviceType,
		"ip_address":         session.IPAddress,
		"last_service":       session.LastService,
		"last_action":        session.LastAction,
	}).Info("Security analysis completed")
}
