package governance

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
)

// Campaign represents a certification campaign.
type Campaign struct {
	ID          string     `json:"id" db:"id"`
	TenantID    string     `json:"tenant_id" db:"tenant_id"`
	Name        string     `json:"name" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	Status      string     `json:"status" db:"status"` // draft, active, completed, cancelled
	ReviewerID  string     `json:"reviewer_id" db:"reviewer_id"`
	StartDate   *time.Time `json:"start_date,omitempty" db:"start_date"`
	EndDate     *time.Time `json:"end_date,omitempty" db:"end_date"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// CertificationItem represents an item to be reviewed in a campaign.
type CertificationItem struct {
	ID              string     `json:"id" db:"id"`
	CampaignID      string     `json:"campaign_id" db:"campaign_id"`
	TenantID        string     `json:"tenant_id" db:"tenant_id"`
	UserID          string     `json:"user_id" db:"user_id"`
	ResourceType    string     `json:"resource_type" db:"resource_type"`
	ResourceID      string     `json:"resource_id" db:"resource_id"`
	ResourceName    string     `json:"resource_name,omitempty" db:"resource_name"`
	Decision        *string    `json:"decision,omitempty" db:"decision"` // approve, revoke, nil
	DecisionAt      *time.Time `json:"decision_at,omitempty" db:"decision_at"`
	DecisionComment *string    `json:"decision_comment,omitempty" db:"decision_comment"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

// CreateCampaignInput holds input for creating a campaign.
type CreateCampaignInput struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	ReviewerID  string     `json:"reviewer_id"`
	StartDate   *time.Time `json:"start_date,omitempty"`
	EndDate     *time.Time `json:"end_date,omitempty"`
}

// CampaignList holds a list of campaigns.
type CampaignList struct {
	Campaigns []Campaign `json:"campaigns"`
	Total     int        `json:"total"`
}

// CampaignStore defines storage operations for campaigns.
type CampaignStore interface {
	CreateCampaign(ctx context.Context, c Campaign) (string, error)
	GetCampaign(ctx context.Context, tenantID, id string) (Campaign, error)
	ListCampaigns(ctx context.Context, tenantID, status string) ([]Campaign, error)
	UpdateCampaignStatus(ctx context.Context, id, status string) error
	DeleteCampaign(ctx context.Context, tenantID, id string) error

	// Items
	CreateItem(ctx context.Context, item CertificationItem) (string, error)
	GetItem(ctx context.Context, itemID string) (CertificationItem, error)
	ListItems(ctx context.Context, campaignID, decision string) ([]CertificationItem, error)
	ListItemsByReviewer(ctx context.Context, tenantID, reviewerID string) ([]CertificationItem, error)
	UpdateItemDecision(ctx context.Context, itemID, decision, comment string) error
}

type campaignStore struct {
	db *sqlx.DB
}

// NewCampaignStore creates a new campaign store.
func NewCampaignStore(db *sqlx.DB) CampaignStore {
	return &campaignStore{db: db}
}

func (s *campaignStore) CreateCampaign(ctx context.Context, c Campaign) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO certification_campaigns (tenant_id, name, description, status, reviewer_id, start_date, end_date)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		c.TenantID, c.Name, c.Description, "draft", c.ReviewerID, c.StartDate, c.EndDate,
	).Scan(&id)
	return id, err
}

func (s *campaignStore) GetCampaign(ctx context.Context, tenantID, id string) (Campaign, error) {
	var c Campaign
	err := s.db.GetContext(ctx, &c,
		`SELECT * FROM certification_campaigns WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return c, err
}

func (s *campaignStore) ListCampaigns(ctx context.Context, tenantID, status string) ([]Campaign, error) {
	var campaigns []Campaign
	query := `SELECT * FROM certification_campaigns WHERE tenant_id = $1`
	args := []interface{}{tenantID}
	if status != "" {
		query += ` AND status = $2`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`
	err := s.db.SelectContext(ctx, &campaigns, query, args...)
	return campaigns, err
}

func (s *campaignStore) UpdateCampaignStatus(ctx context.Context, id, status string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certification_campaigns SET status = $1, updated_at = NOW() WHERE id = $2`,
		status, id)
	return err
}

func (s *campaignStore) DeleteCampaign(ctx context.Context, tenantID, id string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM certification_campaigns WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return err
}

func (s *campaignStore) CreateItem(ctx context.Context, item CertificationItem) (string, error) {
	var id string
	err := s.db.QueryRowxContext(ctx,
		`INSERT INTO certification_items (campaign_id, tenant_id, user_id, resource_type, resource_id, resource_name)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		item.CampaignID, item.TenantID, item.UserID, item.ResourceType, item.ResourceID, item.ResourceName,
	).Scan(&id)
	return id, err
}

func (s *campaignStore) GetItem(ctx context.Context, itemID string) (CertificationItem, error) {
	var item CertificationItem
	err := s.db.GetContext(ctx, &item, `SELECT * FROM certification_items WHERE id = $1`, itemID)
	return item, err
}

func (s *campaignStore) ListItems(ctx context.Context, campaignID, decision string) ([]CertificationItem, error) {
	var items []CertificationItem
	query := `SELECT * FROM certification_items WHERE campaign_id = $1`
	args := []interface{}{campaignID}
	if decision != "" {
		query += ` AND decision = $2`
		args = append(args, decision)
	} else {
		query += ` AND decision IS NULL` // Pending items
	}
	query += ` ORDER BY created_at`
	err := s.db.SelectContext(ctx, &items, query, args...)
	return items, err
}

func (s *campaignStore) ListItemsByReviewer(ctx context.Context, tenantID, reviewerID string) ([]CertificationItem, error) {
	var items []CertificationItem
	query := `
		SELECT i.* 
		FROM certification_items i
		JOIN certification_campaigns c ON i.campaign_id = c.id
		WHERE c.tenant_id = $1 AND c.reviewer_id = $2 AND c.status = 'active' AND i.decision IS NULL
		ORDER BY c.created_at, i.user_id
	`
	err := s.db.SelectContext(ctx, &items, query, tenantID, reviewerID)
	return items, err
}

func (s *campaignStore) UpdateItemDecision(ctx context.Context, itemID, decision, comment string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE certification_items SET decision = $1, decision_comment = $2, decision_at = NOW() WHERE id = $3`,
		decision, comment, itemID)
	return err
}
