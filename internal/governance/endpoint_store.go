package governance

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
)

// Device represents a registered corporate endpoint.
type Device struct {
	ID               string    `json:"id" db:"id"`
	TenantID         string    `json:"tenant_id" db:"tenant_id"`
	UserID           string    `json:"user_id" db:"user_id"`
	DeviceIdentifier string    `json:"device_identifier" db:"device_identifier"`
	OS               string    `json:"os" db:"os"`
	OSVersion        string    `json:"os_version" db:"os_version"`
	IsManaged        bool      `json:"is_managed" db:"is_managed"`
	IsCompliant      bool      `json:"is_compliant" db:"is_compliant"`
	LastSeenAt       time.Time `json:"last_seen_at" db:"last_seen_at"`
	RiskScore        int       `json:"risk_score" db:"risk_score"`
	TrustStatus      string    `json:"trust_status" db:"-"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

func (d *Device) DeriveTrustStatus() {
	if d.IsCompliant {
		d.TrustStatus = "trusted"
	} else if d.IsManaged {
		d.TrustStatus = "untrusted"
	} else {
		d.TrustStatus = "pending"
	}
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
	query := `INSERT INTO devices (tenant_id, user_id, device_identifier, os, os_version, is_managed, is_compliant)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) 
		 ON CONFLICT (tenant_id, device_identifier) DO UPDATE SET os_version = $5, last_seen_at = NOW(), updated_at = NOW()
		 RETURNING id`
	err := r.db.QueryRowContext(ctx, query,
		d.TenantID, d.UserID, d.DeviceIdentifier, d.OS, d.OSVersion, d.IsManaged, d.IsCompliant).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to register device: %w", err)
	}
	return id, nil
}

func (r *sqlEndpointRepository) GetDevice(ctx context.Context, tenantID, id string) (Device, error) {
	var d Device
	err := r.db.GetContext(ctx, &d, `SELECT * FROM devices WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err == nil {
		d.DeriveTrustStatus()
	}
	return d, err
}

func (r *sqlEndpointRepository) ListDevices(ctx context.Context, tenantID string) ([]Device, error) {
	var devices []Device
	err := r.db.SelectContext(ctx, &devices, `SELECT * FROM devices WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	if err == nil {
		for i := range devices {
			devices[i].DeriveTrustStatus()
		}
	}
	return devices, err
}

func (r *sqlEndpointRepository) UpdateDeviceStatus(ctx context.Context, tenantID, id, status string) error {
	compliant := status == "trusted"
	_, err := r.db.ExecContext(ctx, `UPDATE devices SET is_compliant = $1, updated_at = NOW() WHERE id = $2 AND tenant_id = $3`, compliant, id, tenantID)
	return err
}

func (r *sqlEndpointRepository) GetDevicesByUser(ctx context.Context, tenantID, userID string) ([]Device, error) {
	var devices []Device
	err := r.db.SelectContext(ctx, &devices, `SELECT * FROM devices WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	if err == nil {
		for i := range devices {
			devices[i].DeriveTrustStatus()
		}
	}
	return devices, err
}
