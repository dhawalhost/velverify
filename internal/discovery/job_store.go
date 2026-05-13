package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// JobStatus represents the current state of a discovery scan.
type JobStatus string

const (
	JobStatusQueued     JobStatus = "queued"
	JobStatusProcessing JobStatus = "processing"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
)

// JobState contains the metadata for a discovery scan job.
type JobState struct {
	ID         string     `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Status     JobStatus  `json:"status"`
	Progress   int        `json:"progress"` // 0-100
	Message    string     `json:"message,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// JobStore defines the persistence layer for scan job metadata.
type JobStore interface {
	Create(ctx context.Context, jobID, tenantID string) error
	Update(ctx context.Context, jobID string, updateFn func(*JobState)) error
	Get(ctx context.Context, jobID string) (*JobState, error)
}

type redisJobStore struct {
	client    redis.UniversalClient
	ttl       time.Duration
	keyPrefix string
}

// NewRedisJobStore creates a new Redis-backed job store.
func NewRedisJobStore(client redis.UniversalClient) JobStore {
	if client == nil {
		return NewNoOpJobStore()
	}
	return &redisJobStore{
		client:    client,
		ttl:       24 * time.Hour,
		keyPrefix: "discovery:job:",
	}
}

type noOpJobStore struct{}

// NewNoOpJobStore returns a JobStore that does nothing (for environments without Redis).
func NewNoOpJobStore() JobStore {
	return &noOpJobStore{}
}

func (s *noOpJobStore) Create(ctx context.Context, jobID, tenantID string) error {
	return nil
}

func (s *noOpJobStore) Update(ctx context.Context, jobID string, updateFn func(*JobState)) error {
	return nil
}

func (s *noOpJobStore) Get(ctx context.Context, jobID string) (*JobState, error) {
	return nil, fmt.Errorf("job store unavailable (Redis not configured)")
}

func (s *redisJobStore) key(jobID string) string {
	return s.keyPrefix + jobID
}

func (s *redisJobStore) Create(ctx context.Context, jobID, tenantID string) error {
	state := &JobState{
		ID:        jobID,
		TenantID:  tenantID,
		Status:    JobStatusQueued,
		StartedAt: time.Now(),
	}

	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal job state: %w", err)
	}

	return s.client.Set(ctx, s.key(jobID), data, s.ttl).Err()
}

func (s *redisJobStore) Update(ctx context.Context, jobID string, updateFn func(*JobState)) error {
	key := s.key(jobID)

	// In a high-concurrency environment, we should use a Lua script or WATCH/MULTI
	// for atomic updates. For this scan tracking, a simple GET-UPDATE-SET is sufficient.
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		return fmt.Errorf("failed to get job state: %w", err)
	}

	var state JobState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to unmarshal job state: %w", err)
	}

	updateFn(&state)

	newData, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal updated job state: %w", err)
	}

	return s.client.Set(ctx, key, newData, s.ttl).Err()
}

func (s *redisJobStore) Get(ctx context.Context, jobID string) (*JobState, error) {
	data, err := s.client.Get(ctx, s.key(jobID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, fmt.Errorf("job not found")
		}
		return nil, fmt.Errorf("failed to get job state: %w", err)
	}

	var state JobState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal job state: %w", err)
	}

	return &state, nil
}
