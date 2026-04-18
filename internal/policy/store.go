package policy

import (
	"context"

	"github.com/jmoiron/sqlx"
)

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new policy repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (r *sqlRepository) List(ctx context.Context, tenantID string) ([]Policy, error) {
	var policies []Policy
	err := r.db.SelectContext(ctx, &policies, `SELECT * FROM tenant_policies WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	return policies, err
}

func (r *sqlRepository) Get(ctx context.Context, tenantID, id string) (Policy, error) {
	var p Policy
	err := r.db.GetContext(ctx, &p, `SELECT * FROM tenant_policies WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return p, err
}

func (r *sqlRepository) Create(ctx context.Context, p Policy) (string, error) {
	var id string
	query := `INSERT INTO tenant_policies (tenant_id, name, rule_type, rule_data, is_enabled)
		 VALUES ($1, $2, $3, $4, $5) RETURNING id`
	err := r.db.QueryRowxContext(ctx, query, p.TenantID, p.Name, p.RuleType, p.RuleData, p.IsEnabled).Scan(&id)
	return id, err
}

func (r *sqlRepository) Update(ctx context.Context, p Policy) error {
	_, err := r.db.ExecContext(ctx,
		`UPDATE tenant_policies SET name = $1, rule_type = $2, rule_data = $3, is_enabled = $4, updated_at = NOW()
		 WHERE id = $5 AND tenant_id = $6`,
		p.Name, p.RuleType, p.RuleData, p.IsEnabled, p.ID, p.TenantID)
	return err
}

func (r *sqlRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM tenant_policies WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (r *sqlRepository) GetByType(ctx context.Context, tenantID string, ruleType RuleType) ([]Policy, error) {
	var policies []Policy
	err := r.db.SelectContext(ctx, &policies,
		`SELECT * FROM tenant_policies WHERE tenant_id = $1 AND rule_type = $2 AND is_enabled = true`,
		tenantID, string(ruleType))
	return policies, err
}
