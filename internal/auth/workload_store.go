package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

type sqlWorkloadRepository struct {
	db *sqlx.DB
}

// NewWorkloadRepository creates a new SQL workload repository.
func NewWorkloadRepository(db *sqlx.DB) WorkloadRepository {
	return &sqlWorkloadRepository{db: db}
}

func (r *sqlWorkloadRepository) Create(ctx context.Context, w Workload) (string, error) {
	query := `
		INSERT INTO workloads (tenant_id, name, service_handle, client_id, client_secret_hash, metadata)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`
	var id string
	err := r.db.QueryRowxContext(ctx, query,
		w.TenantID,
		w.Name,
		w.ServiceHandle,
		w.ClientID,
		w.ClientSecretHash,
		w.Metadata,
	).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to create workload: %w", err)
	}
	return id, nil
}

func (r *sqlWorkloadRepository) GetByID(ctx context.Context, tenantID, id string) (Workload, error) {
	var w Workload
	query := `SELECT * FROM workloads WHERE id = $1 AND tenant_id = $2`
	err := r.db.GetContext(ctx, &w, query, id, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workload{}, fmt.Errorf("workload not found")
		}
		return Workload{}, err
	}
	return w, nil
}

func (r *sqlWorkloadRepository) GetByClientID(ctx context.Context, clientID string) (Workload, error) {
	var w Workload
	query := `SELECT * FROM workloads WHERE client_id = $1`
	err := r.db.GetContext(ctx, &w, query, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Workload{}, fmt.Errorf("workload not found")
		}
		return Workload{}, err
	}
	return w, nil
}

func (r *sqlWorkloadRepository) Update(ctx context.Context, id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	query := "UPDATE workloads SET "
	args := []interface{}{}
	i := 1
	for k, v := range updates {
		query += fmt.Sprintf("%s = $%d, ", k, i)
		args = append(args, v)
		i++
	}
	query = query[:len(query)-2] + fmt.Sprintf(" WHERE id = $%d", i)
	args = append(args, id)

	_, err := r.db.ExecContext(ctx, query, args...)
	return err
}

func (r *sqlWorkloadRepository) Delete(ctx context.Context, tenantID, id string) error {
	query := `DELETE FROM workloads WHERE id = $1 AND tenant_id = $2`
	_, err := r.db.ExecContext(ctx, query, id, tenantID)
	return err
}

func (r *sqlWorkloadRepository) List(ctx context.Context, tenantID string) ([]Workload, error) {
	var workloads []Workload
	query := `SELECT * FROM workloads WHERE tenant_id = $1 ORDER BY created_at DESC`
	err := r.db.SelectContext(ctx, &workloads, query, tenantID)
	return workloads, err
}
