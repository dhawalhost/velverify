package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/middleware"
)

func generateTestCertPEM() (string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-device-client",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func TestMTLS_Middleware_Verification(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	tenantID := uuid.New().String()
	deviceStore := &mockDeviceStore{devices: make(map[string]*Device)}
	svc := &authService{deviceStore: deviceStore}
	h := &HTTPHandler{
		svc:    svc,
		logger: zap.NewNop(),
	}

	r.POST("/api/v1/devices/register", middleware.TenantExtractor(middleware.TenantConfig{
		HeaderName: "X-Tenant-ID",
	}), mTLSAuthMiddleware(), h.registerDevice)

	// 1. Send Request Without Certificate
	req1, _ := http.NewRequest("POST", "/api/v1/devices/register", bytes.NewBuffer([]byte(`{}`)))
	req1.Header.Set("X-Tenant-ID", tenantID)
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401 when missing cert, got %d", w1.Code)
	}

	// 2. Send Request With Valid Certificate
	certPEM, err := generateTestCertPEM()
	if err != nil {
		t.Fatalf("failed to generate test cert: %v", err)
	}

	payload := RegisterDeviceRequest{
		DeviceIdentifier: "device-mtls-123",
		OS:               "macOS",
	}
	body, _ := json.Marshal(payload)
	req2, _ := http.NewRequest("POST", "/api/v1/devices/register", bytes.NewBuffer(body))
	req2.Header.Set("X-Tenant-ID", tenantID)
	req2.Header.Set("X-Client-Cert", certPEM)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusCreated {
		t.Errorf("expected status 201, got %d. Body: %s", w2.Code, w2.Body.String())
	}
}
