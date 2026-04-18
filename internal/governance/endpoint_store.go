package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Device represents a registered corporate endpoint.
type Device struct {
	ID          string    `json:"id" db:"id"`
	TenantID    string    `json:"tenant_id" db:"tenant_id"`
	UserID      string    `json:"user_id" db:"user_id"`
	Serial      string    `json:"serial" db:"serial"`
	Platform    string    `json:"platform" db:"platform"` // macOS, Windows, Linux, iOS, Android
	OSVersion   string    `json:"os_version" db:"os_version"`
	TrustStatus string    `json:"trust_status" db:"trust_status"` // pending, trusted, untrusted
	LastScanAt  time.Time `json:"last_scan_at" db:"last_scan_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// EndpointRepository defines persistence for devices.
type EndpointRepository interface {
	RegisterDevice(ctx context.Context, d Device) (string, error)
	GetDevice(ctx context.Context, tenantID, id string) (Device, error)
	ListDevices(ctx context.Context, tenantID string) ([]Device, error)
	UpdateDeviceStatus(ctx context.Context, tenantID, id, status string) error
	GetDevicesByUser(ctx context.Context, tenantID, userID string) ([]Device, error)
}

type sqlEndpointRepository struct {
	db *sqlx.DB
}

func NewEndpointRepository(db *sqlx.DB) EndpointRepository {
	return &sqlEndpointRepository{db: db}
}

func (r *sqlEndpointRepository) RegisterDevice(ctx context.Context, d Device) (string, error) {
	var id string
	query := `INSERT INTO devices (tenant_id, user_id, serial, platform, os_version, trust_status)
		 VALUES ($1, $2, $3, $4, $5, $6) 
		 ON CONFLICT (tenant_id, serial) DO UPDATE SET os_version = $5, updated_at = NOW()
		 RETURNING id`
	err := r.db.QueryRowContext(ctx, query, 
		d.TenantID, d.UserID, d.Serial, d.Platform, d.OSVersion, "pending").Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to register device: %w", err)
	}
	return id, nil
}

func (r *sqlEndpointRepository) GetDevice(ctx context.Context, tenantID, id string) (Device, error) {
	var d Device
	err := r.db.GetContext(ctx, &d, `SELECT * FROM devices WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return d, err
}

func (r *sqlEndpointRepository) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	var devices []Device
	err := r.db.SelectContext(ctx, &devices, `SELECT * FROM devices WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	return devices, err
}

func (r *sqlEndpointRepository) UpdateDeviceStatus(ctx context.Context, tenantID, id, status string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE devices SET trust_status = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`, status, id, tenantID)
	return err
}

func (r *sqlEndpointRepository) GetDevicesByUser(ctx context.Context, tenantID, userID string) ([]Device, error) {
	var devices []Device
	err := r.db.SelectContext(ctx, &devices, `SELECT * FROM devices WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	return devices, err
}
