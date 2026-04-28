package auth

import (
	"context"
	"fmt"
	"math"
	"time"

	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

type coord struct {
	lat float64
	lon float64
}

var countryCoords = map[string]coord{
	"US": {37.0902, -95.7129},
	"GB": {55.3781, -3.4360},
	"IN": {20.5937, 78.9629},
	"DE": {51.1657, 10.4515},
	"FR": {46.2276, 2.2137},
	"CN": {35.8617, 104.1954},
	"JP": {36.2048, 138.2529},
	"AU": {-25.2744, 133.7751},
	"BR": {-14.2350, -51.9253},
	"CA": {56.1304, -106.3468},
}

func haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const R = 3958.8 // Earth radius in miles
	
	dLat := (lat2 - lat1) * math.Pi / 180.0
	dLon := (lon2 - lon1) * math.Pi / 180.0
	
	lat1Rad := lat1 * math.Pi / 180.0
	lat2Rad := lat2 * math.Pi / 180.0
	
	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Sin(dLon/2)*math.Sin(dLon/2)*math.Cos(lat1Rad)*math.Cos(lat2Rad)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))
	
	return R * c
}

// RiskLevel enum
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "LOW"
	RiskLevelMedium RiskLevel = "MEDIUM"
	RiskLevelHigh   RiskLevel = "HIGH"
)

// RiskScore represents the calculated risk.
type RiskScore struct {
	Score   int       `json:"score"` // 0-100
	Level   RiskLevel `json:"level"`
	Factors []string  `json:"factors"`
}

// GeoClient resolves an IP address to an ISO 3166-1 alpha-2 country code.
// The zero value (nil) disables geo-lookup.
type GeoClient interface {
	LookupCountry(ip string) (string, error)
}

// RiskEngine evaluates authentication risk.
type RiskEngine struct {
	deviceStore   DeviceRepository
	signalStore   SignalRepository
	ipPolicyStore IPPolicyRepository
	geoClient     GeoClient
	logger        *zap.Logger
}

func NewRiskEngine(deviceStore DeviceRepository, signalStore SignalRepository, logger *zap.Logger) *RiskEngine {
	return &RiskEngine{
		deviceStore: deviceStore,
		signalStore: signalStore,
		logger:      logger,
	}
}

// WithIPPolicy attaches an IP policy repository and optional geo client to the risk engine.
func (e *RiskEngine) WithIPPolicy(store IPPolicyRepository, geo GeoClient) *RiskEngine {
	e.ipPolicyStore = store
	e.geoClient = geo
	return e
}

// Evaluate calculates the risk score for a login attempt.
func (e *RiskEngine) Evaluate(ctx context.Context, userID, deviceID, ip string) (RiskScore, error) {
	score := 0
	factors := []string{}

	// 1. Device Posture Check
	if deviceID != "" {
		device, err := e.deviceStore.GetByID(ctx, deviceID)
		if err != nil {
			e.logger.Error("Failed to fetch device for risk eval", zap.Error(err))
			// Treat unknown device as elevated risk
			score += 20
			factors = append(factors, "device_lookup_error")
		} else if device == nil {
			score += 20
			factors = append(factors, "unknown_device")
		} else {
			if !device.IsCompliant {
				score += 50
				factors = append(factors, "device_non_compliant")
			}
			if device.RiskScore > 0 {
				score += device.RiskScore
				factors = append(factors, "device_reported_risk")
			}
		}
	} else {
		// No device ID — new/unregistered device, slight risk bump
		score += 10
		factors = append(factors, "no_device_id")
	}

	// 2. Signal Check (CAE events in last 24h + Impossible Travel)
	if e.signalStore != nil {
		now := time.Now()
		since := now.Add(-24 * time.Hour)

		// 2.1 Critical Event Check
		event, err := e.signalStore.GetLatestCriticalEvent(ctx, userID, since)
		if err == nil && event != nil {
			score += 30
			factors = append(factors, "recent_security_event: "+event.EventType)
		}

		// 2.2 Impossible Travel Check
		lastLogin, err := e.signalStore.GetLatestSuccess(ctx, userID)
		if err == nil && lastLogin != nil && lastLogin.IPAddress != ip && e.geoClient != nil {
			// Resolve both IPs to coordinates (mocking coordinates for this logic)
			// In a full implementation, GeoClient would return Lat/Lon
			// For now, we'll implement the velocity check logic structure
			velocity, err := e.calculateVelocity(lastLogin.IPAddress, ip, lastLogin.Timestamp, now)
			if err == nil && velocity > 500 { // 500 mph threshold
				score += 60 // Significant risk bump
				factors = append(factors, fmt.Sprintf("impossible_travel: %.1f mph", velocity))
			}
		}
	}

	// 3. IP Policy Check (tenant-scoped block list + geo restriction)
	if e.ipPolicyStore != nil && ip != "" {
		tenantID := tenantIDFromCtx(ctx)
		if tenantID != "" {
			policies, err := e.ipPolicyStore.ListBlocked(ctx, tenantID)
			if err != nil {
				e.logger.Warn("Failed to load IP policies for risk eval", zap.Error(err))
			} else {
				blocked, policy := EvaluateIP(ip, policies)
				if blocked {
					score = 100 // Hard block — immediately deny
					reason := "ip_block_list"
					if policy != nil && policy.Reason != "" {
						reason = "ip_blocked: " + policy.Reason
					}
					factors = append(factors, reason)
				}
			}

			// Geo-restriction check (only when not already hard-blocked)
			if score < 100 && e.geoClient != nil {
				country, err := e.geoClient.LookupCountry(ip)
				if err != nil {
					e.logger.Warn("Geo lookup failed", zap.String("ip", ip), zap.Error(err))
				} else if country != "" {
					// Re-fetch all block policies (may include country entries) or reuse above slice
					all, err2 := e.ipPolicyStore.ListBlocked(ctx, tenantID)
					if err2 == nil {
						for _, p := range all {
							if p.Type == IPPolicyBlock && p.Country != nil && *p.Country == country {
								if score < 80 {
									score = 80
								}
								factors = append(factors, "geo_blocked_country: "+country)
								break
							}
						}
					}
				}
			}
		}
	}

	// Cap score at 100
	if score > 100 {
		score = 100
	}

	// Determine Level
	level := RiskLevelLow
	if score >= 80 {
		level = RiskLevelHigh
	} else if score >= 40 {
		level = RiskLevelMedium
	}

	return RiskScore{
		Score:   score,
		Level:   level,
		Factors: factors,
	}, nil
}

// calculateVelocity estimates travel speed between two IPs in miles per hour.
func (e *RiskEngine) calculateVelocity(ip1, ip2 string, t1, t2 time.Time) (float64, error) {
	duration := t2.Sub(t1).Hours()
	if duration <= 0 || ip1 == ip2 {
		return 0, nil
	}

	distance := 0.0
	if e.geoClient != nil {
		country1, err1 := e.geoClient.LookupCountry(ip1)
		country2, err2 := e.geoClient.LookupCountry(ip2)
		if err1 == nil && err2 == nil && country1 != "" && country2 != "" {
			c1, ok1 := countryCoords[country1]
			c2, ok2 := countryCoords[country2]
			if ok1 && ok2 {
				distance = haversine(c1.lat, c1.lon, c2.lat, c2.lon)
			} else {
				// Fallback to standard country-to-country distance if not mapped
				if country1 != country2 {
					distance = 1000.0
				}
			}
		}
	}

	if distance == 0.0 && ip1 != ip2 {
		e.logger.Warn("Impossible Travel velocity check bypassed - coordinate resolution not fully implemented",
			zap.String("ip1", ip1),
			zap.String("ip2", ip2))
	}

	return distance / duration, nil
}

// tenantIDFromCtx is a convenience wrapper around the middleware package's exported helper.
func tenantIDFromCtx(ctx context.Context) string {
	id, _ := middleware.TenantIDFromContext(ctx)
	return id
}
