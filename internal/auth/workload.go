package auth

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// JSONMap represents a generic JSON object.
type JSONMap map[string]interface{}

// Scan implements the sql.Scanner interface for database -> struct mapping.
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = make(JSONMap)
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return errors.New("type assertion to []byte/string failed")
	}

	return json.Unmarshal(bytes, j)
}

// Value implements the driver.Valuer interface for struct -> database mapping.
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return json.Marshal(make(JSONMap))
	}
	return json.Marshal(j)
}

// Workload represents a non-human identity (agent, service, or machine).
type Workload struct {
	ID               string     `json:"id" db:"id"`
	TenantID         string     `json:"tenant_id" db:"tenant_id"`
	Name             string     `json:"name" db:"name"`
	ServiceHandle    string     `json:"service_handle" db:"service_handle"` // e.g. "service:auth"
	ClientID         string     `json:"client_id" db:"client_id"`
	ClientSecretHash string     `json:"-" db:"client_secret_hash"`
	Metadata         JSONMap    `json:"metadata" db:"metadata"`
	Status           string     `json:"status" db:"status"` // active, suspended, rotated
	LastUsedAt       *time.Time `json:"last_used_at" db:"last_used_at"`
	CreatedAt        time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" db:"updated_at"`
}

// WorkloadRepository defines the persistence layer for non-human identities.
type WorkloadRepository interface {
	Create(ctx context.Context, workload Workload) (string, error)
	GetByID(ctx context.Context, tenantID, id string) (Workload, error)
	GetByClientID(ctx context.Context, clientID string) (Workload, error)
	Update(ctx context.Context, id string, updates map[string]interface{}) error
	Delete(ctx context.Context, tenantID, id string) error
	List(ctx context.Context, tenantID string) ([]Workload, error)
}
