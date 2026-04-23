package authz

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const (
	MaxDepth = 10 // Prevent infinite recursion
)

// Engine performs recursive relationship checks with granular caching.
type Engine struct {
	repo  Repository
	log   *zap.Logger
	cache sync.Map // Key: tenantID:subID:subType:rel:ns:objID -> Value: bool
}

func NewEngine(repo Repository, log *zap.Logger) *Engine {
	return &Engine{
		repo: repo,
		log:  log,
	}
}

// Check determines if a subject has a specific relation to an object.
func (e *Engine) Check(ctx context.Context, tenantID, subID, subType, rel, ns, objID string) (bool, error) {
	// 1. Check cache first
	cacheKey := fmt.Sprintf("%s:%s:%s:%s:%s:%s", tenantID, subID, subType, rel, ns, objID)
	if val, ok := e.cache.Load(cacheKey); ok {
		return val.(bool), nil
	}

	// 2. Perform recursive check
	allowed, err := e.checkRecursive(ctx, tenantID, subID, subType, rel, ns, objID, 0)
	if err == nil {
		e.cache.Store(cacheKey, allowed)
	}
	return allowed, err
}

// InvalidateByTuple clears cache entries affected by a specific tuple change.
func (e *Engine) InvalidateByTuple(tenantID string, tuple RelationTuple) {
	// For granular invalidation, we clear entries where either the object or subject matches.
	// This ensures that any path through these nodes is re-evaluated.
	e.cache.Range(func(key, value interface{}) bool {
		k := key.(string)
		// Format: tenantID:subID:subType:rel:ns:objID
		if fmt.Sprintf("%s:", tenantID) == k[:len(tenantID)+1] {
			// If key involves the modified object or subject, invalidate it
			if strings.Contains(k, tuple.ObjectID) || strings.Contains(k, tuple.SubjectID) {
				e.cache.Delete(key)
			}
		}
		return true
	})
}

func (e *Engine) ListTuples(ctx context.Context, tenantID string, query Query) ([]RelationTuple, error) {
	return e.repo.ListTuples(ctx, tenantID, query)
}

// Traverse recursively collects all relation tuples starting from a subject handle.
func (e *Engine) Traverse(ctx context.Context, tenantID, subjectID string) ([]RelationTuple, error) {
	var results []RelationTuple
	visited := make(map[string]bool)

	// BFS for relationship propagation
	queue := []string{subjectID}
	visited[subjectID] = true

	depth := 0
	for len(queue) > 0 && depth < MaxDepth {
		var nextQueue []string
		for _, currentSub := range queue {
			// Find tuples where currentSub is the subject
			tuples, err := e.repo.ListTuples(ctx, tenantID, Query{
				SubjectID: currentSub,
			})
			if err != nil {
				return nil, err
			}

			for _, t := range tuples {
				results = append(results, t)

				// If ObjectID hasn't been visited, add to next iteration
				// This allows us to find indirect memberships (Group -> Group -> Role)
				if !visited[t.ObjectID] {
					visited[t.ObjectID] = true
					nextQueue = append(nextQueue, t.ObjectID)
				}
			}
		}
		queue = nextQueue
		depth++
	}

	return results, nil
}

func (e *Engine) checkRecursive(ctx context.Context, tenantID, subID, subType, rel, ns, objID string, depth int) (bool, error) {
	if depth > MaxDepth {
		return false, fmt.Errorf("max depth exceeded in graph traversal")
	}

	// 1. DIRECT CHECK: (ns:objID)#rel@sub
	tuples, err := e.repo.ListTuples(ctx, tenantID, Query{
		Namespace:   ns,
		ObjectID:    objID,
		Relation:    rel,
		SubjectType: subType,
		SubjectID:   subID,
	})
	if err == nil && len(tuples) > 0 {
		return true, nil
	}

	// 2. USERSET CHECK (Indirection)
	// Example: (folder:A)#viewer @ (project:P)#member
	// If the above tuple exists, we then need to check:
	// does (subID) have 'member' on (project:P)?

	// We look for any tuple matching (ns:objID)#rel where subject is a 'set'
	indirectionTuples, err := e.repo.ListTuples(ctx, tenantID, Query{
		Namespace:   ns,
		ObjectID:    objID,
		Relation:    rel,
		SubjectType: "set",
	})
	if err != nil {
		return false, err
	}

	for _, t := range indirectionTuples {
		// t.SubjectID is the 'parent' object (e.g. 'project:P')
		// t.SubjectRelation is the relation on that parent (e.g. 'member')

		// t.SubjectID is expected to be in format "namespace:objectID"
		// but since we only have subject_id in the table, we might need a parser
		// For WardSeal ReBAC, we store SubjectID as the ID and assume SubjectType context.
		// Usually SubjectID = actual ID, and for 'set', the SubjectRelation tells us what to check.

		if t.SubjectRelation == nil {
			continue
		}

		// Recurse: Does the user have the SubjectRelation on t.SubjectID?
		// Note: We need to know the namespace of t.SubjectID.
		// For now, we assume the subject namespace is part of the 'Namespace' config or implicit.
		// In a full Zanzibar, the subject_id is actually another object.

		// TODO: Improve subject namespace resolution.
		// For this MVP, we assume relationships flow within the same namespace or specific hardcoded ones.

		allowed, err := e.checkRecursive(ctx, tenantID, subID, subType, *t.SubjectRelation, ns, t.SubjectID, depth+1)
		if err == nil && allowed {
			return true, nil
		}
	}

	return false, nil
}
