package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/dhawalhost/wardseal/pkg/database"
)

type sqlWorkloadRepository struct {
	db *sqlx.DB
}

// NewWorkloadRepository creates a new SQL workload repository.
func NewWorkloadRepository(db *sqlx.DB) WorkloadRepository {
	return &sqlWorkloadRepository{db: db}
}

func (r *sqlWorkloadRepository) Create(ctx context.Context, w Workload) (string, error) {
	var id string
	err := database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `
			INSERT INTO workloads (tenant_id, name, service_handle, client_id, client_secret_hash, metadata)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id
		`
		return tx.QueryRowxContext(ctx, query,
			w.TenantID,
			w.Name,
			w.ServiceHandle,
			w.ClientID,
			w.ClientSecretHash,
			w.Metadata,
		).Scan(&id)
	})
	if err != nil {
		return "", fmt.Errorf("failed to create workload: %w", err)
	}
	return id, nil
}

func (r *sqlWorkloadRepository) GetByID(ctx context.Context, tenantID, id string) (Workload, error) {
	var w Workload
	var found bool
	err := database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `SELECT * FROM workloads WHERE id = $1 AND tenant_id = $2`
		err := tx.GetContext(ctx, &w, query, id, tenantID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				found = false
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return Workload{}, err
	}
	if !found {
		return Workload{}, fmt.Errorf("workload not found")
	}
	return w, nil
}

func (r *sqlWorkloadRepository) GetByClientID(ctx context.Context, clientID string) (Workload, error) {
	var w Workload
	var found bool
	err := database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `SELECT * FROM workloads WHERE client_id = $1`
		err := tx.GetContext(ctx, &w, query, clientID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				found = false
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return Workload{}, err
	}
	if !found {
		return Workload{}, fmt.Errorf("workload not found")
	}
	return w, nil
}

func (r *sqlWorkloadRepository) Update(ctx context.Context, id string, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	return database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
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

		_, err := tx.ExecContext(ctx, query, args...)
		return err
	})
}

func (r *sqlWorkloadRepository) Delete(ctx context.Context, tenantID, id string) error {
	return database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `DELETE FROM workloads WHERE id = $1 AND tenant_id = $2`
		_, err := tx.ExecContext(ctx, query, id, tenantID)
		return err
	})
}

func (r *sqlWorkloadRepository) List(ctx context.Context, tenantID string) ([]Workload, error) {
	var workloads []Workload
	err := database.RunInTenantTx(ctx, r.db, func(tx *sqlx.Tx) error {
		query := `SELECT * FROM workloads WHERE tenant_id = $1 ORDER BY created_at DESC`
		return tx.SelectContext(ctx, &workloads, query, tenantID)
	})
	return workloads, err
}
