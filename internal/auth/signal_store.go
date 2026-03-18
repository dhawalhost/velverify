package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// SecurityEvent represents a critical event that may impact access.
type SecurityEvent struct {
	ID        string    `db:"id" json:"id"`
	TenantID  string    `db:"tenant_id" json:"tenant_id"`
	SubjectID string    `db:"subject_id" json:"subject_id"`
	EventType string    `db:"event_type" json:"event_type"` // e.g., "password-changed", "session-revoked"
	EventTime time.Time `db:"event_time" json:"event_time"`
	JTI       string    `db:"jti" json:"jti,omitempty"` // Optional: if event targets a specific token
	Reason    string    `db:"reason" json:"reason,omitempty"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// SignalRepository defines storage for security events.
type SignalRepository interface {
	Ingest(ctx context.Context, event *SecurityEvent) error
	GetLatestCriticalEvent(ctx context.Context, subjectID string, since time.Time) (*SecurityEvent, error)
}

type sqlSignalRepository struct {
	db *sqlx.DB
}

// NewSignalRepository creates a new SignalRepository.
func NewSignalRepository(db *sqlx.DB) SignalRepository {
	return &sqlSignalRepository{db: db}
}

func (r *sqlSignalRepository) Ingest(ctx context.Context, event *SecurityEvent) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.EventTime.IsZero() {
		event.EventTime = time.Now()
	}
	event.CreatedAt = time.Now()

	query := `
		INSERT INTO security_events (id, tenant_id, subject_id, event_type, event_time, jti, reason, created_at)
		VALUES (:id, :tenant_id, :subject_id, :event_type, :event_time, :jti, :reason, :created_at)
	`
	_, err := r.db.NamedExecContext(ctx, query, event)
	return err
}

func (r *sqlSignalRepository) GetLatestCriticalEvent(ctx context.Context, subjectID string, since time.Time) (*SecurityEvent, error) {
	// Check for events that revoke access (password changes, compromised sessions/devices)
	// For MVP, we check ANY event in this table for the subject since the time.
	// In reality, we'd filter by critical types.
	query := `
		SELECT * FROM security_events 
		WHERE subject_id = $1 AND event_time > $2
		ORDER BY event_time DESC
		LIMIT 1
	`
	var event SecurityEvent
	err := r.db.GetContext(ctx, &event, query, subjectID, since)
	if err != nil {
		return nil, err // Returns error if no rows, likely sql.ErrNoRows which caller handles
	}
	return &event, nil
}
