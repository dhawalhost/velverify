package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

type RedisWebAuthnSessionStoreConfig struct {
	Addr      string
	Password  string
	DB        int
	TTL       time.Duration
	KeyPrefix string
}

type redisWebAuthnSessionRepository struct {
	client    redis.UniversalClient
	ttl       time.Duration
	keyPrefix string
}

func NewRedisWebAuthnSessionRepository(cfg RedisWebAuthnSessionStoreConfig) (WebAuthnSessionRepository, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "webauthn:session:"
	}

	importStrings := func(s string) []string {
		var res []string
		for _, part := range strings.Split(s, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				res = append(res, trimmed)
			}
		}
		return res
	}

	client := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:    importStrings(cfg.Addr),
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &redisWebAuthnSessionRepository{
		client:    client,
		ttl:       cfg.TTL,
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

func (s *redisWebAuthnSessionRepository) key(userID string) string {
	return s.keyPrefix + userID
}

func (s *redisWebAuthnSessionRepository) Set(ctx context.Context, userID string, session webauthn.SessionData) {
	payload, err := json.Marshal(session)
	if err != nil {
		return
	}
	_ = s.client.Set(ctx, s.key(userID), payload, s.ttl).Err()
}

func (s *redisWebAuthnSessionRepository) Get(ctx context.Context, userID string) (webauthn.SessionData, bool) {
	value, err := s.client.Get(ctx, s.key(userID)).Bytes()
	if err != nil {
		return webauthn.SessionData{}, false
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(value, &session); err != nil {
		return webauthn.SessionData{}, false
	}

	return session, true
}

func (s *redisWebAuthnSessionRepository) Delete(ctx context.Context, userID string) {
	_ = s.client.Del(ctx, s.key(userID)).Err()
}
