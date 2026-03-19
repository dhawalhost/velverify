package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
)

// Event represents an audit log entry.
type Event struct {
	ID           string          `json:"id" db:"id"`
	TenantID     string          `json:"tenant_id" db:"tenant_id"`
	Timestamp    time.Time       `json:"timestamp" db:"timestamp"`
	ActorID      *string         `json:"actor_id,omitempty" db:"actor_id"`
	ActorType    string          `json:"actor_type" db:"actor_type"` // user, system, service
	Action       string          `json:"action" db:"action"`
	ResourceType string          `json:"resource_type" db:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty" db:"resource_id"`
	ResourceName *string         `json:"resource_name,omitempty" db:"resource_name"`
	Details      json.RawMessage `json:"details,omitempty" db:"details"`
	IPAddress    *string         `json:"ip_address,omitempty" db:"ip_address"`
	UserAgent    *string         `json:"user_agent,omitempty" db:"user_agent"`
	Outcome      string          `json:"outcome" db:"outcome"` // success, failure
}

// LogInput holds input for creating an audit log entry.
type LogInput struct {
	TenantID     string
	ActorID      *string
	ActorType    string
	Action       string
	ResourceType string
	ResourceID   *string
	ResourceName *string
	Details      interface{}
	IPAddress    *string
	UserAgent    *string
	Outcome      string
}

// QueryParams holds parameters for querying audit logs.
type QueryParams struct {
	TenantID     string
	ActorID      *string
	Action       *string
	ResourceType *string
	ResourceID   *string
	Outcome      *string
	StartTime    *time.Time
	EndTime      *time.Time
	Limit        int
	Offset       int
}

// Repository defines audit log storage operations.
type Repository interface {
	Log(ctx context.Context, e Event) (string, error)
	Query(ctx context.Context, params QueryParams) ([]Event, int, error)
	GetEvent(ctx context.Context, tenantID, id string) (Event, error)
}

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new audit repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (s *sqlRepository) Log(ctx context.Context, e Event) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO audit_logs (tenant_id, actor_id, actor_type, action, resource_type, resource_id, resource_name, details, ip_address, user_agent, outcome)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id`,
		e.TenantID, e.ActorID, e.ActorType, e.Action, e.ResourceType, e.ResourceID, e.ResourceName, e.Details, e.IPAddress, e.UserAgent, e.Outcome,
	).Scan(&id)
	return id, err
}

func (s *sqlRepository) Query(ctx context.Context, params QueryParams) ([]Event, int, error) {
	// Build query dynamically
	query := `SELECT * FROM audit_logs WHERE tenant_id = $1`
	countQuery := `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1`
	args := []interface{}{params.TenantID}
	argIdx := 2

	if params.ActorID != nil {
		query += ` AND actor_id = $` + itoa(argIdx)
		countQuery += ` AND actor_id = $` + itoa(argIdx)
		args = append(args, *params.ActorID)
		argIdx++
	}
	if params.Action != nil {
		query += ` AND action = $` + itoa(argIdx)
		countQuery += ` AND action = $` + itoa(argIdx)
		args = append(args, *params.Action)
		argIdx++
	}
	if params.ResourceType != nil {
		query += ` AND resource_type = $` + itoa(argIdx)
		countQuery += ` AND resource_type = $` + itoa(argIdx)
		args = append(args, *params.ResourceType)
		argIdx++
	}
	if params.ResourceID != nil {
		query += ` AND resource_id = $` + itoa(argIdx)
		countQuery += ` AND resource_id = $` + itoa(argIdx)
		args = append(args, *params.ResourceID)
		argIdx++
	}
	if params.Outcome != nil {
		query += ` AND outcome = $` + itoa(argIdx)
		countQuery += ` AND outcome = $` + itoa(argIdx)
		args = append(args, *params.Outcome)
		argIdx++
	}
	if params.StartTime != nil {
		query += ` AND timestamp >= $` + itoa(argIdx)
		countQuery += ` AND timestamp >= $` + itoa(argIdx)
		args = append(args, *params.StartTime)
		argIdx++
	}
	if params.EndTime != nil {
		query += ` AND timestamp <= $` + itoa(argIdx)
		countQuery += ` AND timestamp <= $` + itoa(argIdx)
		args = append(args, *params.EndTime)
		argIdx++
	}

	// Get total count
	var total int
	if err := s.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, err
	}

	// Add pagination
	query += ` ORDER BY timestamp DESC`
	if params.Limit > 0 {
		query += ` LIMIT $` + itoa(argIdx)
		args = append(args, params.Limit)
		argIdx++
	}
	if params.Offset > 0 {
		query += ` OFFSET $` + itoa(argIdx)
		args = append(args, params.Offset)
	}

	var events []Event
	if err := s.db.SelectContext(ctx, &events, query, args...); err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

func (s *sqlRepository) GetEvent(ctx context.Context, tenantID, id string) (Event, error) {
	var e Event
	err := s.db.GetContext(ctx, &e, `SELECT * FROM audit_logs WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return e, err
}

func itoa(i int) string {
	return strconv.Itoa(i)
}
