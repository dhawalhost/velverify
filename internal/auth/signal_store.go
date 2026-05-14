package auth

import (
	"context"
	"database/sql"
	"errors"
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

// LoginSignal specifically tracks authentication success.
type LoginSignal struct {
	ID        string    `db:"id"`
	TenantID  string    `db:"tenant_id"`
	SubjectID string    `db:"subject_id"`
	IPAddress string    `db:"ip_address"`
	Timestamp time.Time `db:"timestamp"`
}

// UserRisk represents the current security posture of a user.
type UserRisk struct {
	UserID          string    `db:"user_id"`
	TenantID        string    `db:"tenant_id"`
	Score           int       `db:"score"`
	Level           string    `db:"level"`
	Factors         string    `db:"factors"` // JSONB string
	LastEvaluatedAt time.Time `db:"last_evaluated_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// SignalRepository defines storage for security events and risk state.
type SignalRepository interface {
	Ingest(ctx context.Context, event *SecurityEvent) error
	IngestLogin(ctx context.Context, signal *LoginSignal) error
	GetLatestCriticalEvent(ctx context.Context, subjectID string, since time.Time) (*SecurityEvent, error)
	GetLatestSuccess(ctx context.Context, subjectID string) (*LoginSignal, error)

	// Risk Persistence
	UpdateUserRisk(ctx context.Context, risk UserRisk) error
	GetUserRisk(ctx context.Context, tenantID, userID string) (*UserRisk, error)
	GetHighRiskUsers(ctx context.Context, tenantID string, threshold int) ([]UserRisk, error)
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
	query := `
		SELECT * FROM security_events 
		WHERE subject_id = $1 AND event_time > $2
		ORDER BY event_time DESC
		LIMIT 1
	`
	var event SecurityEvent
	err := r.db.GetContext(ctx, &event, query, subjectID, since)
	if err != nil {
		return nil, err
	}
	return &event, nil
}

func (r *sqlSignalRepository) IngestLogin(ctx context.Context, s *LoginSignal) error {
	if s.ID == "" {
		s.ID = uuid.New().String()
	}
	if s.Timestamp.IsZero() {
		s.Timestamp = time.Now()
	}
	query := `
		INSERT INTO login_signals (id, tenant_id, subject_id, ip_address, timestamp)
		VALUES ($1, $2, $3, $4, $5)
	`
	_, err := r.db.ExecContext(ctx, query, s.ID, s.TenantID, s.SubjectID, s.IPAddress, s.Timestamp)
	return err
}

func (r *sqlSignalRepository) GetLatestSuccess(ctx context.Context, subjectID string) (*LoginSignal, error) {
	query := `
		SELECT * FROM login_signals 
		WHERE subject_id = $1 
		ORDER BY timestamp DESC
		LIMIT 1
	`
	var s LoginSignal
	err := r.db.GetContext(ctx, &s, query, subjectID)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *sqlSignalRepository) GetUserRisk(ctx context.Context, tenantID, userID string) (*UserRisk, error) {
	var risk UserRisk
	query := `SELECT * FROM user_risk_levels WHERE tenant_id = $1 AND user_id = $2`
	err := r.db.GetContext(ctx, &risk, query, tenantID, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &risk, nil
}

func (r *sqlSignalRepository) UpdateUserRisk(ctx context.Context, risk UserRisk) error {
	query := `
		INSERT INTO user_risk_levels (user_id, tenant_id, score, level, factors, last_evaluated_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			score = EXCLUDED.score,
			level = EXCLUDED.level,
			factors = EXCLUDED.factors,
			last_evaluated_at = EXCLUDED.last_evaluated_at,
			updated_at = NOW()
	`
	_, err := r.db.ExecContext(ctx, query,
		risk.UserID,
		risk.TenantID,
		risk.Score,
		risk.Level,
		risk.Factors,
		risk.LastEvaluatedAt,
	)
	return err
}

func (r *sqlSignalRepository) GetHighRiskUsers(ctx context.Context, tenantID string, threshold int) ([]UserRisk, error) {
	var risks []UserRisk
	query := `SELECT * FROM user_risk_levels WHERE score >= $1 AND tenant_id = $2 ORDER BY score DESC`
	err := r.db.SelectContext(ctx, &risks, query, threshold, tenantID)
	return risks, err
}
