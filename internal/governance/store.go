package governance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jmoiron/sqlx"
)

// Repository defines database operations for governance.
type Repository interface {
	CreateRequest(ctx context.Context, req AccessRequest) (string, error)
	GetRequest(ctx context.Context, tenantID, id string) (AccessRequest, error)
	ListRequests(ctx context.Context, tenantID, status string) ([]AccessRequest, error)
	UpdateRequestStatus(ctx context.Context, id, status string) error

	// IP Access Policies
	CreateIPPolicy(ctx context.Context, p IPPolicy) (string, error)
	ListIPPolicies(ctx context.Context, tenantID string) ([]IPPolicy, error)
	DeleteIPPolicy(ctx context.Context, tenantID, id string) error

	// Safety Actions
	CreateSafetyAction(ctx context.Context, action SafetyAction) (string, error)
	GetSafetyAction(ctx context.Context, tenantID, id string) (SafetyAction, error)
	ListSafetyActions(ctx context.Context, tenantID, status string) ([]SafetyAction, error)
	UpdateSafetyActionStatus(ctx context.Context, id, status string) error
}

type sqlRepository struct {
	db *sqlx.DB
}

// NewRepository creates a new governance repository.
func NewRepository(db *sqlx.DB) Repository {
	return &sqlRepository{db: db}
}

func (s *sqlRepository) CreateRequest(ctx context.Context, req AccessRequest) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO access_requests (tenant_id, requester_id, requester_type, resource_type, resource_id, reason, duration, status, device_id, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
		req.TenantID, req.RequesterID, req.RequesterType, req.ResourceType, req.ResourceID, req.Reason, req.Duration, "pending", req.DeviceID, req.Metadata).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("failed to create access request: %w", err)
	}
	return id, nil
}

func (s *sqlRepository) GetRequest(ctx context.Context, tenantID, id string) (AccessRequest, error) {
	var req AccessRequest
	err := s.db.GetContext(ctx, &req, `SELECT * FROM access_requests WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AccessRequest{}, fmt.Errorf("request not found")
		}
		return AccessRequest{}, err
	}
	return req, nil
}

func (s *sqlRepository) ListRequests(ctx context.Context, tenantID, status string) ([]AccessRequest, error) {
	query := `SELECT * FROM access_requests WHERE tenant_id = $1`
	args := []interface{}{tenantID}

	if status != "" {
		query += ` AND status = $2`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`

	var requests []AccessRequest
	err := s.db.SelectContext(ctx, &requests, query, args...)
	if err != nil {
		return nil, err
	}
	return requests, nil
}

func (s *sqlRepository) UpdateRequestStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE access_requests SET status = $1, updated_at = NOW() WHERE id = $2`, status, id)
	return err
}

func (s *sqlRepository) CreateIPPolicy(ctx context.Context, p IPPolicy) (string, error) {
	query := `
		INSERT INTO ip_policy (id, tenant_id, type, cidr, country, reason)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := s.db.ExecContext(ctx, query, p.ID, p.TenantID, p.Type, p.CIDR, p.CountryCode, p.Reason)
	return p.ID, err
}

func (s *sqlRepository) ListIPPolicies(ctx context.Context, tenantID string) ([]IPPolicy, error) {
	var policies []IPPolicy
	err := s.db.SelectContext(ctx, &policies,
		`SELECT id, tenant_id, type, cidr, country as country_code, reason, created_at FROM ip_policy WHERE tenant_id = $1 ORDER BY created_at DESC`, tenantID)
	return policies, err
}

func (s *sqlRepository) DeleteIPPolicy(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM ip_policy WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

// Safety Action Implementation

func (s *sqlRepository) CreateSafetyAction(ctx context.Context, action SafetyAction) (string, error) {
	var id string
	query := `INSERT INTO safety_actions (tenant_id, action_type, target_id, metadata, status, reason)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`
	err := s.db.QueryRowContext(ctx, query,
		action.TenantID, action.ActionType, action.TargetID, action.Metadata, "pending", action.Reason).Scan(&id)
	return id, err
}

func (s *sqlRepository) GetSafetyAction(ctx context.Context, tenantID, id string) (SafetyAction, error) {
	var action SafetyAction
	err := s.db.GetContext(ctx, &action, `SELECT * FROM safety_actions WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return action, err
}

func (s *sqlRepository) ListSafetyActions(ctx context.Context, tenantID, status string) ([]SafetyAction, error) {
	var actions []SafetyAction
	query := `SELECT * FROM safety_actions WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if status != "" {
		query += ` AND status = $2`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`
	err := s.db.SelectContext(ctx, &actions, query, args...)
	return actions, err
}

func (s *sqlRepository) UpdateSafetyActionStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE safety_actions SET status = $1, updated_at = NOW() WHERE id = $2`, status, id)
	return err
}
