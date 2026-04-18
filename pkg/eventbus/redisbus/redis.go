package redisbus

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
)

// redisBus implements eventbus.EventBus using Redis Pub/Sub.
type redisBus struct {
	client *redis.Client
	logger *zap.Logger
	mu     sync.Mutex
	subs   map[string]*redis.PubSub
}

// NewRedisEventBus creates a new EventBus backed by Redis Pub/Sub.
func NewRedisEventBus(client *redis.Client, logger *zap.Logger) eventbus.EventBus {
	return &redisBus{
		client: client,
		logger: logger,
		subs:   make(map[string]*redis.PubSub),
	}
}

// Publish sends an event to the Redis channel (topic).
func (r *redisBus) Publish(ctx context.Context, topic string, payload []byte) error {
	return r.client.Publish(ctx, topic, payload).Err()
}

// Subscribe registers a handler and starts listening to a Redis channel in a background goroutine.
func (r *redisBus) Subscribe(ctx context.Context, topic string, handler eventbus.Handler) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.subs[topic]; exists {
		return fmt.Errorf("already subscribed to topic: %s", topic)
	}

	pubsub := r.client.Subscribe(ctx, topic)
	r.subs[topic] = pubsub

	go func() {
		r.logger.Info("started consuming events", zap.String("topic", topic))
		ch := pubsub.Channel()
		for msg := range ch {
			payload := []byte(msg.Payload)
			
			// Retry loop
			maxRetries := 3
			var lastErr error
			success := false
			
			for i := 0; i < maxRetries; i++ {
				execCtx := context.Background()
				if err := handler(execCtx, payload); err != nil {
					lastErr = err
					r.logger.Warn("event handler failed, retrying...",
						zap.String("topic", topic),
						zap.Int("attempt", i+1),
						zap.Error(err),
					)
					time.Sleep(time.Duration(i+1) * 100 * time.Millisecond) // Linear backoff
					continue
				}
				success = true
				break
			}

			if !success {
				r.logger.Error("event handler exhausted retries, pushing to DLQ",
					zap.String("topic", topic),
					zap.Error(lastErr),
				)
				
				// Publish to DLQ
				dlqPayload, _ := json.Marshal(map[string]interface{}{
					"original_topic": topic,
					"payload":        string(payload),
					"error":           lastErr.Error(),
					"failed_at":      time.Now().Format(time.RFC3339),
				})
				_ = r.Publish(context.Background(), "dlq:failed_events", dlqPayload)
			}
		}
		r.logger.Info("stopped consuming events", zap.String("topic", topic))
	}()

	return nil
}

// Close unsubscribes from all channels and cleans up.
func (r *redisBus) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var firstErr error
	for topic, pubsub := range r.subs {
		if err := pubsub.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(r.subs, topic)
	}
	return firstErr
}
