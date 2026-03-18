package auth

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Device represents a user's device.
type Device struct {
	ID               string    `db:"id" json:"id"`
	TenantID         string    `db:"tenant_id" json:"tenant_id"`
	UserID           string    `db:"user_id" json:"user_id"`
	DeviceIdentifier string    `db:"device_identifier" json:"device_identifier"`
	OS               string    `db:"os" json:"os"`
	OSVersion        string    `db:"os_version" json:"os_version"`
	IsManaged        bool      `db:"is_managed" json:"is_managed"`
	IsCompliant      bool      `db:"is_compliant" json:"is_compliant"`
	LastSeenAt       time.Time `db:"last_seen_at" json:"last_seen_at"`
	RiskScore        int       `db:"risk_score" json:"risk_score"`
	CreatedAt        time.Time `db:"created_at" json:"created_at"`
	UpdatedAt        time.Time `db:"updated_at" json:"updated_at"`
}

// DeviceRepository defines the interface for storing and retrieving devices.
type DeviceRepository interface {
	Register(ctx context.Context, device *Device) error
	GetByID(ctx context.Context, id string) (*Device, error)
	GetByIdentifier(ctx context.Context, tenantID, identifier string) (*Device, error)
	UpdatePosture(ctx context.Context, id string, isCompliant bool, riskScore int) error
	ListByUser(ctx context.Context, userID string) ([]Device, error)
	List(ctx context.Context, tenantID string) ([]Device, error)
	Delete(ctx context.Context, id string) error
}

// sqlDeviceRepository implements DeviceRepository using sqlx.
type sqlDeviceRepository struct {
	db *sqlx.DB
}

// NewDeviceRepository creates a new DeviceRepository backed by sqlx.
func NewDeviceRepository(db *sqlx.DB) DeviceRepository {
	return &sqlDeviceRepository{db: db}
}

func (r *sqlDeviceRepository) Register(ctx context.Context, device *Device) error {
	if device.ID == "" {
		device.ID = uuid.New().String()
	}
	device.CreatedAt = time.Now()
	device.UpdatedAt = time.Now()
	device.LastSeenAt = time.Now()

	query := `
		INSERT INTO devices (id, tenant_id, user_id, device_identifier, os, os_version, is_managed, is_compliant, last_seen_at, risk_score, created_at, updated_at)
		VALUES (:id, :tenant_id, :user_id, :device_identifier, :os, :os_version, :is_managed, :is_compliant, :last_seen_at, :risk_score, :created_at, :updated_at)
		ON CONFLICT (tenant_id, device_identifier) DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			updated_at = EXCLUDED.updated_at,
			os_version = EXCLUDED.os_version,
			is_managed = EXCLUDED.is_managed -- Allow re-registration to update status
	`
	_, err := r.db.NamedExecContext(ctx, query, device)
	return err
}

func (r *sqlDeviceRepository) GetByID(ctx context.Context, id string) (*Device, error) {
	var device Device
	query := `SELECT * FROM devices WHERE id = $1`
	err := r.db.GetContext(ctx, &device, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

func (r *sqlDeviceRepository) GetByIdentifier(ctx context.Context, tenantID, identifier string) (*Device, error) {
	var device Device
	query := `SELECT * FROM devices WHERE tenant_id = $1 AND device_identifier = $2`
	err := r.db.GetContext(ctx, &device, query, tenantID, identifier)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &device, nil
}

func (r *sqlDeviceRepository) UpdatePosture(ctx context.Context, id string, isCompliant bool, riskScore int) error {
	query := `
		UPDATE devices 
		SET is_compliant = $1, risk_score = $2, updated_at = $3 
		WHERE id = $4
	`
	_, err := r.db.ExecContext(ctx, query, isCompliant, riskScore, time.Now(), id)
	return err
}

func (r *sqlDeviceRepository) ListByUser(ctx context.Context, userID string) ([]Device, error) {
	devices := []Device{}
	query := `SELECT * FROM devices WHERE user_id = $1`
	err := r.db.SelectContext(ctx, &devices, query, userID)
	return devices, err
}

func (r *sqlDeviceRepository) List(ctx context.Context, tenantID string) ([]Device, error) {
	devices := []Device{}
	query := `SELECT * FROM devices WHERE tenant_id = $1 ORDER BY last_seen_at DESC`
	err := r.db.SelectContext(ctx, &devices, query, tenantID)
	return devices, err
}

func (r *sqlDeviceRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM devices WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}
