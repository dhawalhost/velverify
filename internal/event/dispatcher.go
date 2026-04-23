package event

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/webhook"
)

// Event represents a system event.
type Event struct {
	ID        string      `json:"id"`
	TenantID  string      `json:"tenant_id"`
	Type      string      `json:"type"` // e.g. "user.created"
	Payload   interface{} `json:"payload"`
	Timestamp time.Time   `json:"timestamp"`
}

// Dispatcher handles event publication.
type Dispatcher struct {
	webhookSvc webhook.Service
	logger     *zap.Logger
	httpClient *http.Client
}

// NewDispatcher creates a new event dispatcher.
func NewDispatcher(webhookSvc webhook.Service, logger *zap.Logger) *Dispatcher {
	return &Dispatcher{
		webhookSvc: webhookSvc,
		logger:     logger,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Publish fires an event asynchronously.
func (d *Dispatcher) Publish(ctx context.Context, event Event) {
	// In a real system, this would push to a queue (NATS/Kafka).
	// For MVP, we launch a goroutine.
	go d.processEvent(context.WithoutCancel(ctx), event)
}

func (d *Dispatcher) processEvent(ctx context.Context, event Event) {
	d.logger.Info("Processing event", zap.String("type", event.Type), zap.String("tenant", event.TenantID))

	// 1. Find interested webhooks
	hooks, err := d.webhookSvc.GetWebhooksForEvent(ctx, event.TenantID, event.Type)
	if err != nil {
		d.logger.Error("Failed to fetch webhooks for event", zap.Error(err))
		return
	}

	if len(hooks) == 0 {
		return
	}

	// 2. Dispatch to each webhook
	payloadBytes, err := json.Marshal(event)
	if err != nil {
		d.logger.Error("Failed to marshal event payload", zap.Error(err))
		return
	}

	for _, hook := range hooks {
		go d.sendWebhook(ctx, hook, payloadBytes, event.ID)
	}
}

func (d *Dispatcher) sendWebhook(ctx context.Context, hook webhook.Webhook, payload []byte, eventID string) {
	req, err := http.NewRequestWithContext(ctx, "POST", hook.URL, bytes.NewBuffer(payload))
	if err != nil {
		d.logger.Error("Failed to create webhook request", zap.Error(err))
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-WardSeal-Event-ID", eventID)

	// Calculate HMAC signature
	mac := hmac.New(sha256.New, []byte(hook.Secret))
	mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-WardSeal-Signature", "sha256="+signature)

	resp, err := d.httpClient.Do(req)
	if err != nil {
		d.logger.Error("Webhook delivery failed", zap.String("url", hook.URL), zap.Error(err))
		// simplistic retry logic could go here
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 300 {
		d.logger.Warn("Webhook received non-2xx response",
			zap.String("url", hook.URL),
			zap.Int("status", resp.StatusCode))
	} else {
		d.logger.Info("Webhook delivered successfully", zap.String("url", hook.URL))
	}
}
