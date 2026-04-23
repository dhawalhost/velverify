-- Phase 2: Relationship-Based Access Control (ReBAC)
-- This implements a Zanzibar-style relationship store.

CREATE TABLE relationship_tuples (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(255) NOT NULL,
    
    -- object_type (e.g., 'folder', 'project', 'app')
    namespace VARCHAR(255) NOT NULL,
    object_id VARCHAR(255) NOT NULL,
    
    -- relation (e.g., 'owner', 'editor', 'viewer', 'parent')
    relation VARCHAR(255) NOT NULL,
    
    -- subject
    subject_type VARCHAR(255) NOT NULL, -- 'user' or 'set'
    subject_id VARCHAR(255) NOT NULL,
    subject_relation VARCHAR(255),       -- Optional: used for indirection (userset)
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Optimize for: "Who has [relation] on [object]?"
CREATE INDEX idx_tuples_object ON relationship_tuples (tenant_id, namespace, object_id, relation);

-- Optimize for: "What can [subject] access?"
CREATE INDEX idx_tuples_subject ON relationship_tuples (tenant_id, subject_id, subject_type);

-- Prevent duplicate relationship definitions
CREATE UNIQUE INDEX idx_tuples_unique ON relationship_tuples (tenant_id, namespace, object_id, relation, subject_type, subject_id, COALESCE(subject_relation, ''));

-- Namespaces Metadata (Optional: For future schema enforcement)
CREATE TABLE authz_namespaces (
    tenant_id VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    config JSONB NOT NULL, -- Stores relation rewrite rules (e.g., 'editor' implies 'viewer')
    PRIMARY KEY (tenant_id, name)
);
