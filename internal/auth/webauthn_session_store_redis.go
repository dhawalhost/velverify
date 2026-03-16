package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/go-webauthn/webauthn/webauthn"
)

type RedisWebAuthnSessionStoreConfig struct {
	Addr      string
	Password  string
	DB        int
	TTL       time.Duration
	KeyPrefix string
}

type redisWebAuthnSessionStore struct {
	client    *redis.Client
	ttl       time.Duration
	keyPrefix string
}

func NewRedisWebAuthnSessionStore(cfg RedisWebAuthnSessionStoreConfig) (WebAuthnSessionStore, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("redis address is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "webauthn:session:"
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &redisWebAuthnSessionStore{
		client:    client,
		ttl:       cfg.TTL,
		keyPrefix: cfg.KeyPrefix,
	}, nil
}

func (s *redisWebAuthnSessionStore) key(userID string) string {
	return s.keyPrefix + userID
}

func (s *redisWebAuthnSessionStore) Set(userID string, session webauthn.SessionData) {
	payload, err := json.Marshal(session)
	if err != nil {
		return
	}
	_ = s.client.Set(context.Background(), s.key(userID), payload, s.ttl).Err()
}

func (s *redisWebAuthnSessionStore) Get(userID string) (webauthn.SessionData, bool) {
	value, err := s.client.Get(context.Background(), s.key(userID)).Bytes()
	if err != nil {
		return webauthn.SessionData{}, false
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(value, &session); err != nil {
		return webauthn.SessionData{}, false
	}

	return session, true
}

func (s *redisWebAuthnSessionStore) Delete(userID string) {
	_ = s.client.Del(context.Background(), s.key(userID)).Err()
}
