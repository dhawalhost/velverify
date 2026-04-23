package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// sqlProvisioningService implements ProvisioningService using a SQL database as a queue.
type sqlProvisioningService struct {
	db       *sqlx.DB
	registry Registry
	logger   *zap.Logger
}

// NewProvisioningService creates a new SQL-backed provisioning service.
func NewProvisioningService(db *sqlx.DB, registry Registry, logger *zap.Logger) ProvisioningService {
	return &sqlProvisioningService{
		db:       db,
		registry: registry,
		logger:   logger,
	}
}

// EnqueueTask adds a provisioning task to the queue.
func (s *sqlProvisioningService) EnqueueTask(ctx context.Context, task ProvisioningTask) (string, error) {
	payloadBytes, err := json.Marshal(task.Payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	var id string
	err = s.db.QueryRowxContext(ctx,
		`INSERT INTO provisioning_tasks (tenant_id, connector_id, operation, resource_type, resource_id, payload, max_retries)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		task.TenantID, task.ConnectorID, task.Operation, task.ResourceType, task.ResourceID, payloadBytes, task.MaxRetries,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to enqueue task: %w", err)
	}

	s.logger.Info("Provisioning task enqueued",
		zap.String("task_id", id),
		zap.String("operation", task.Operation),
		zap.String("connector_id", task.ConnectorID),
	)
	return id, nil
}

// Start runs the background worker loop.
func (s *sqlProvisioningService) Start(ctx context.Context) {
	s.logger.Info("Provisioning background worker started")
	ticker := time.NewTicker(time.Second * 5)

	go func() {
		for {
			select {
			case <-ticker.C:
				tasks, err := s.listPendingTasks(ctx, 10)
				if err != nil {
					s.logger.Error("Failed to list pending tasks", zap.Error(err))
					continue
				}
				for _, t := range tasks {
					if err := s.ExecuteTask(ctx, t.ID); err != nil {
						s.logger.Error("Failed to execute task", zap.String("task_id", t.ID), zap.Error(err))
					}
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// ExecuteTask executes a single provisioning task.
func (s *sqlProvisioningService) ExecuteTask(ctx context.Context, taskID string) error {
	// Mark as processing
	_, err := s.db.ExecContext(ctx,
		`UPDATE provisioning_tasks SET status = 'processing' WHERE id = $1`, taskID)
	if err != nil {
		return err
	}

	// Get task
	var t taskRow
	if err := s.db.GetContext(ctx, &t, `SELECT * FROM provisioning_tasks WHERE id = $1`, taskID); err != nil {
		return err
	}
	task := t.toTask()

	// Get connector
	conn, ok := s.registry.Get(task.ConnectorID)
	if !ok {
		return s.failTask(ctx, taskID, "connector not found")
	}

	// Execute operation
	execErr := s.executeOperation(ctx, conn, task)
	if execErr != nil {
		// Handle retry
		if task.RetryCount < task.MaxRetries {
			backoff := time.Duration(1<<task.RetryCount) * time.Minute // Exponential backoff
			if _, err := s.db.ExecContext(ctx,
				`UPDATE provisioning_tasks SET status = 'pending', retry_count = retry_count + 1, 
				 scheduled_at = NOW() + $1, error_message = $2 WHERE id = $3`,
				backoff, execErr.Error(), taskID); err != nil {
				return err
			}
			return nil
		}
		return s.failTask(ctx, taskID, execErr.Error())
	}

	// Mark as completed
	_, err = s.db.ExecContext(ctx,
		`UPDATE provisioning_tasks SET status = 'completed', processed_at = NOW() WHERE id = $1`, taskID)
	return err
}

func (s *sqlProvisioningService) listPendingTasks(ctx context.Context, limit int) ([]ProvisioningTask, error) {
	var rows []taskRow
	err := s.db.SelectContext(ctx, &rows,
		`SELECT * FROM provisioning_tasks 
		 WHERE status = 'pending' AND scheduled_at <= NOW()
		 ORDER BY scheduled_at LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}

	tasks := make([]ProvisioningTask, len(rows))
	for i, r := range rows {
		tasks[i] = r.toTask()
	}
	return tasks, nil
}

func (s *sqlProvisioningService) failTask(ctx context.Context, taskID, errMsg string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE provisioning_tasks SET status = 'failed', error_message = $1, processed_at = NOW() WHERE id = $2`,
		errMsg, taskID)
	return err
}

func (s *sqlProvisioningService) executeOperation(ctx context.Context, conn Connector, task ProvisioningTask) error {
	switch task.Operation {
	case "create_user":
		var user User
		if b, ok := task.Payload.([]byte); ok {
			if err := json.Unmarshal(b, &user); err != nil {
				return err
			}
		}
		_, err := conn.CreateUser(ctx, user)
		return err

	case "update_user":
		var user User
		if b, ok := task.Payload.([]byte); ok {
			if err := json.Unmarshal(b, &user); err != nil {
				return err
			}
		}
		return conn.UpdateUser(ctx, task.ResourceID, user)

	case "delete_user":
		return conn.DeleteUser(ctx, task.ResourceID)

	case "add_to_group":
		var payload struct {
			UserID  string `json:"user_id"`
			GroupID string `json:"group_id"`
		}
		if b, ok := task.Payload.([]byte); ok {
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}
		}
		return conn.AddUserToGroup(ctx, payload.UserID, payload.GroupID)

	case "remove_from_group":
		var payload struct {
			UserID  string `json:"user_id"`
			GroupID string `json:"group_id"`
		}
		if b, ok := task.Payload.([]byte); ok {
			if err := json.Unmarshal(b, &payload); err != nil {
				return err
			}
		}
		return conn.RemoveUserFromGroup(ctx, payload.UserID, payload.GroupID)

	default:
		return fmt.Errorf("unknown operation: %s", task.Operation)
	}
}

// taskRow represents a DB row.
type taskRow struct {
	ID           string     `db:"id"`
	TenantID     string     `db:"tenant_id"`
	ConnectorID  string     `db:"connector_id"`
	Operation    string     `db:"operation"`
	ResourceType string     `db:"resource_type"`
	ResourceID   *string    `db:"resource_id"`
	Payload      []byte     `db:"payload"`
	Status       string     `db:"status"`
	ErrorMessage *string    `db:"error_message"`
	RetryCount   int        `db:"retry_count"`
	MaxRetries   int        `db:"max_retries"`
	CreatedAt    time.Time  `db:"created_at"`
	ProcessedAt  *time.Time `db:"processed_at"`
	ScheduledAt  time.Time  `db:"scheduled_at"`
}

func (r taskRow) toTask() ProvisioningTask {
	t := ProvisioningTask{
		ID:           r.ID,
		TenantID:     r.TenantID,
		ConnectorID:  r.ConnectorID,
		Operation:    r.Operation,
		ResourceType: r.ResourceType,
		Payload:      r.Payload,
		Status:       r.Status,
		RetryCount:   r.RetryCount,
		MaxRetries:   r.MaxRetries,
		CreatedAt:    r.CreatedAt,
		ProcessedAt:  r.ProcessedAt,
	}
	if r.ResourceID != nil {
		t.ResourceID = *r.ResourceID
	}
	if r.ErrorMessage != nil {
		t.ErrorMessage = *r.ErrorMessage
	}
	return t
}
