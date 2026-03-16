package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"golang.org/x/time/rate"
)

var distributedRateLimitScript = redis.NewScript(`
local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("PEXPIRE", KEYS[1], ARGV[1])
end
return current
`)

type RateLimitWindowProfile struct {
	Requests int
	Window   time.Duration
}

type DistributedRateLimitConfig struct {
	RedisClient      *redis.Client
	KeyPrefix        string
	UseTenant        bool
	DefaultProfile   RateLimitWindowProfile
	EndpointProfiles map[string]RateLimitWindowProfile
	DegradedProfile  RateLimitWindowProfile
}

func normalizeProfile(profile RateLimitWindowProfile, fallbackRequests int, fallbackWindow time.Duration) RateLimitWindowProfile {
	if profile.Requests <= 0 {
		profile.Requests = fallbackRequests
	}
	if profile.Window <= 0 {
		profile.Window = fallbackWindow
	}
	return profile
}

func classifyRateLimitEndpoint(path string) string {
	path = strings.ToLower(path)
	switch {
	case strings.Contains(path, "/oauth2/token"):
		return "token"
	case strings.Contains(path, "/api/v1/setup"):
		return "setup"
	case strings.Contains(path, "/webhooks"):
		return "webhook"
	case strings.Contains(path, "/login"):
		return "login"
	default:
		return "default"
	}
}

func buildTenantScope(c *gin.Context, useTenant bool) string {
	if !useTenant {
		return "global"
	}
	tenantID := c.GetHeader(DefaultTenantHeader)
	if tenantID != "" {
		return tenantID
	}
	if resolvedTenantID, err := TenantIDFromGinContext(c); err == nil && resolvedTenantID != "" {
		return resolvedTenantID
	}
	return "global"
}

func distributedFallbackAllow(fallback *IPRateLimiter, scopeKey string) bool {
	return fallback.GetLimiter(scopeKey).Allow()
}

// DistributedRateLimitMiddleware applies Redis-backed fixed-window rate limiting.
// It supports tenant-aware + endpoint-aware buckets and falls back to strict local limits on Redis failures.
func DistributedRateLimitMiddleware(cfg DistributedRateLimitConfig) gin.HandlerFunc {
	keyPrefix := cfg.KeyPrefix
	if keyPrefix == "" {
		keyPrefix = "ratelimit"
	}

	defaultProfile := normalizeProfile(cfg.DefaultProfile, 1200, time.Minute)
	degradedProfile := normalizeProfile(cfg.DegradedProfile, 120, time.Minute)

	profiles := map[string]RateLimitWindowProfile{
		"default": defaultProfile,
	}
	for endpoint, profile := range cfg.EndpointProfiles {
		profiles[endpoint] = normalizeProfile(profile, defaultProfile.Requests, defaultProfile.Window)
	}

	degradedPerSecond := float64(degradedProfile.Requests) / degradedProfile.Window.Seconds()
	if degradedPerSecond <= 0 {
		degradedPerSecond = 1
	}
	fallbackBurst := degradedProfile.Requests
	if fallbackBurst <= 0 {
		fallbackBurst = 1
	}
	fallback := NewIPRateLimiter(rate.Limit(degradedPerSecond), fallbackBurst)

	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		endpoint := classifyRateLimitEndpoint(path)
		profile, ok := profiles[endpoint]
		if !ok {
			profile = defaultProfile
		}

		tenantScope := buildTenantScope(c, cfg.UseTenant)
		ip := c.ClientIP()
		rateScopeKey := tenantScope + ":" + endpoint + ":" + ip

		if cfg.RedisClient == nil {
			if !distributedFallbackAllow(fallback, rateScopeKey) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
				return
			}
			c.Next()
			return
		}

		windowMillis := profile.Window.Milliseconds()
		if windowMillis <= 0 {
			windowMillis = time.Minute.Milliseconds()
		}
		currentWindow := time.Now().UnixMilli() / windowMillis
		redisKey := fmt.Sprintf("%s:%s:%s:%s:%d", keyPrefix, endpoint, tenantScope, ip, currentWindow)

		result, err := distributedRateLimitScript.Run(c.Request.Context(), cfg.RedisClient, []string{redisKey}, windowMillis).Int64()
		if err != nil {
			if !distributedFallbackAllow(fallback, rateScopeKey) {
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
				return
			}
			c.Next()
			return
		}

		if int(result) > profile.Requests {
			retryAfter := int(windowMillis / 1000)
			if retryAfter <= 0 {
				retryAfter = 1
			}
			c.Header("Retry-After", fmt.Sprintf("%d", retryAfter))
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}

		c.Next()
	}
}
