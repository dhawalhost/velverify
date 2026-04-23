package authz

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Repository defines the interface for managing relationship tuples.
type Repository interface {
	CreateTuple(ctx context.Context, tuple *RelationTuple) error
	DeleteTuple(ctx context.Context, tenantID, id string) error
	DeleteByPattern(ctx context.Context, tenantID string, query Query) error
	ListTuples(ctx context.Context, tenantID string, query Query) ([]RelationTuple, error)
	GetNamespace(ctx context.Context, tenantID, name string) (*Namespace, error)
	UpsertNamespace(ctx context.Context, ns *Namespace) error
}

type sqlRepository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (r *sqlRepository) CreateTuple(ctx context.Context, t *RelationTuple) error {
	if t.ID == "" {
		t.ID = uuid.New().String()
	}
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	query := `
		INSERT INTO relationship_tuples (
			id, tenant_id, namespace, object_id, relation, subject_type, subject_id, subject_relation, created_at, updated_at
		) VALUES (
			:id, :tenant_id, :namespace, :object_id, :relation, :subject_type, :subject_id, :subject_relation, :created_at, :updated_at
		) ON CONFLICT (tenant_id, namespace, object_id, relation, subject_type, subject_id, COALESCE(subject_relation, '')) 
		DO UPDATE SET updated_at = NOW()
	`
	_, err := r.db.NamedExecContext(ctx, query, t)
	return err
}

func (r *sqlRepository) DeleteTuple(ctx context.Context, tenantID, id string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM relationship_tuples WHERE tenant_id = $1 AND id = $2", tenantID, id)
	return err
}

func (r *sqlRepository) DeleteByPattern(ctx context.Context, tenantID string, q Query) error {
	sql := "DELETE FROM relationship_tuples WHERE tenant_id = $1"
	args := []interface{}{tenantID}

	i := 2
	if q.Namespace != "" {
		sql += fmt.Sprintf(" AND namespace = $%d", i)
		args = append(args, q.Namespace)
		i++
	}
	if q.ObjectID != "" {
		sql += fmt.Sprintf(" AND object_id = $%d", i)
		args = append(args, q.ObjectID)
		i++
	}
	if q.Relation != "" {
		sql += fmt.Sprintf(" AND relation = $%d", i)
		args = append(args, q.Relation)
		i++
	}
	if q.SubjectID != "" {
		sql += fmt.Sprintf(" AND subject_id = $%d", i)
		args = append(args, q.SubjectID)
	}

	_, err := r.db.ExecContext(ctx, sql, args...)
	return err
}

func (r *sqlRepository) ListTuples(ctx context.Context, tenantID string, q Query) ([]RelationTuple, error) {
	sql := "SELECT * FROM relationship_tuples WHERE tenant_id = $1"
	args := []interface{}{tenantID}

	i := 2
	if q.Namespace != "" {
		sql += fmt.Sprintf(" AND namespace = $%d", i)
		args = append(args, q.Namespace)
		i++
	}
	if q.ObjectID != "" {
		sql += fmt.Sprintf(" AND object_id = $%d", i)
		args = append(args, q.ObjectID)
		i++
	}
	if q.Relation != "" {
		sql += fmt.Sprintf(" AND relation = $%d", i)
		args = append(args, q.Relation)
		i++
	}
	if q.SubjectType != "" {
		sql += fmt.Sprintf(" AND subject_type = $%d", i)
		args = append(args, q.SubjectType)
		i++
	}
	if q.SubjectID != "" {
		sql += fmt.Sprintf(" AND subject_id = $%d", i)
		args = append(args, q.SubjectID)
	}

	var tuples []RelationTuple
	err := r.db.SelectContext(ctx, &tuples, sql+" ORDER BY created_at DESC", args...)
	return tuples, err
}

func (r *sqlRepository) GetNamespace(ctx context.Context, tenantID, name string) (*Namespace, error) {
	var ns Namespace
	err := r.db.GetContext(ctx, &ns, "SELECT * FROM authz_namespaces WHERE tenant_id = $1 AND name = $2", tenantID, name)
	if err != nil {
		return nil, err
	}
	return &ns, nil
}

func (r *sqlRepository) UpsertNamespace(ctx context.Context, ns *Namespace) error {
	query := `
		INSERT INTO authz_namespaces (tenant_id, name, config)
		VALUES (:tenant_id, :name, :config)
		ON CONFLICT (tenant_id, name) DO UPDATE SET config = EXCLUDED.config
	`
	_, err := r.db.NamedExecContext(ctx, query, ns)
	return err
}
