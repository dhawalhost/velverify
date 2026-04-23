package authz

import (
	"time"
)

// RelationTuple represents a Zanzibar-style relationship.
// Pattern: (Namespace:ObjectID)#Relation@(SubjectType:SubjectID)[#SubjectRelation]
type RelationTuple struct {
	ID              string    `db:"id" json:"id"`
	TenantID        string    `db:"tenant_id" json:"tenant_id"`
	Namespace       string    `db:"namespace" json:"namespace"`
	ObjectID        string    `db:"object_id" json:"object_id"`
	Relation        string    `db:"relation" json:"relation"`
	SubjectType     string    `db:"subject_type" json:"subject_type"` // 'user' or 'set'
	SubjectID       string    `db:"subject_id" json:"subject_id"`
	SubjectRelation *string   `db:"subject_relation" json:"subject_relation,omitempty"`
	CreatedAt       time.Time `db:"created_at" json:"created_at"`
	UpdatedAt       time.Time `db:"updated_at" json:"updated_at"`
}

// Namespace defines the schema/rules for a specific object type.
type Namespace struct {
	TenantID string                 `db:"tenant_id" json:"tenant_id"`
	Name     string                 `db:"name" json:"name"`
	Config   map[string]interface{} `db:"config" json:"config"` // Rewrite rules
}

// Query represents a filter for searching tuples.
type Query struct {
	Namespace   string
	ObjectID    string
	Relation    string
	SubjectType string
	SubjectID   string
}
