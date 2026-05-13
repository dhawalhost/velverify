package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// Mock Device Store for EDR tests
type mockDeviceStore struct {
	devices map[string]*Device
}

func (m *mockDeviceStore) Register(ctx context.Context, d *Device) error {
	if m.devices == nil {
		m.devices = make(map[string]*Device)
	}
	if d.DeviceIdentifier == "" {
		d.DeviceIdentifier = uuid.New().String()
	}
	m.devices[d.DeviceIdentifier] = d
	return nil
}
func (m *mockDeviceStore) GetByID(ctx context.Context, id string) (*Device, error) {
	if m.devices == nil {
		return nil, nil
	}
	return m.devices[id], nil
}
func (m *mockDeviceStore) UpdatePosture(ctx context.Context, id string, isCompliant bool, riskScore int) error {
	if m.devices == nil {
		return nil
	}
	if d, ok := m.devices[id]; ok {
		d.IsCompliant = isCompliant
		d.LastSeenAt = time.Now()
	}
	return nil
}
func (m *mockDeviceStore) GetByIdentifier(ctx context.Context, tenantID, identifier string) (*Device, error) {
	if m.devices == nil {
		return nil, nil
	}
	for _, d := range m.devices {
		if d.TenantID == tenantID && d.DeviceIdentifier == identifier {
			return d, nil
		}
	}
	return nil, nil
}

func (m *mockDeviceStore) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	if m.devices == nil {
		return nil, nil
	}
	var res []Device
	for _, d := range m.devices {
		if d.UserID == userID {
			res = append(res, *d)
		}
	}
	return res, nil
}

func (m *mockDeviceStore) List(ctx context.Context, tenantID string) ([]Device, error) {
	return nil, nil
}
func (m *mockDeviceStore) Delete(ctx context.Context, id string) error {
	return nil
}
func (m *mockDeviceStore) GetByUserID(ctx context.Context, tenantID, userID string) ([]Device, error) {
	return nil, nil
}

func TestEDR_CrowdStrike_Webhook(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	deviceStore := &mockDeviceStore{devices: make(map[string]*Device)}
	signalStore := &mockSignalStore{}

	// Register dummy device
	tenantID := uuid.New().String()
	deviceID := "device-123"
	deviceStore.devices[deviceID] = &Device{
		TenantID:         tenantID,
		UserID:           "user-123",
		DeviceIdentifier: deviceID,
		IsCompliant:      true,
	}

	svc := &authService{
		deviceStore: deviceStore,
		signalStore: signalStore,
	}

	h := &HTTPHandler{
		svc:    svc,
		logger: zap.NewNop(),
	}

	r.POST("/api/v1/devices/webhooks/:provider", middleware.TenantExtractor(middleware.TenantConfig{
		HeaderName: "X-Tenant-ID",
	}), h.handleWebhook)

	// 1. Send Compliant Webhook (ZTA >= 50)
	payload1 := CrowdStrikeWebhook{
		DeviceID: deviceID,
		ZTA:      85,
	}
	body1, _ := json.Marshal(payload1)
	req1, _ := http.NewRequest("POST", "/api/v1/devices/webhooks/crowdstrike", bytes.NewBuffer(body1))
	req1.Header.Set("X-Tenant-ID", tenantID)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w1.Code)
	}
	if !deviceStore.devices[deviceID].IsCompliant {
		t.Errorf("expected device to remain compliant")
	}

	// 2. Send Non-Compliant Webhook (ZTA < 50)
	payload2 := CrowdStrikeWebhook{
		DeviceID: deviceID,
		ZTA:      30,
	}
	body2, _ := json.Marshal(payload2)
	req2, _ := http.NewRequest("POST", "/api/v1/devices/webhooks/crowdstrike", bytes.NewBuffer(body2))
	req2.Header.Set("X-Tenant-ID", tenantID)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w2.Code)
	}
	if deviceStore.devices[deviceID].IsCompliant {
		t.Errorf("expected device to be non-compliant")
	}

	// Verify security event was ingested
	event, _ := signalStore.GetLatestCriticalEvent(context.Background(), "user-123", time.Now().Add(-1*time.Hour))
	if event == nil {
		t.Errorf("expected security event to be ingested")
	} else if event.EventType != "device-posture-violation" {
		t.Errorf("unexpected event type: %s", event.EventType)
	}
}
