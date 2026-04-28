package auth

import (
	"context"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnSessionRepository stores transient WebAuthn session state.
// Implementations can be in-memory (dev) or distributed (Redis) for horizontal scaling.
type WebAuthnSessionRepository interface {
	Set(ctx context.Context, userID string, session webauthn.SessionData)
	Get(ctx context.Context, userID string) (webauthn.SessionData, bool)
	Delete(ctx context.Context, userID string)
}

type inMemoryWebAuthnSessionRepository struct {
	mu       sync.RWMutex
	sessions map[string]webauthn.SessionData
}

func newInMemoryWebAuthnSessionRepository() WebAuthnSessionRepository {
	return &inMemoryWebAuthnSessionRepository{
		sessions: make(map[string]webauthn.SessionData),
	}
}

func (s *inMemoryWebAuthnSessionRepository) Set(ctx context.Context, userID string, session webauthn.SessionData) {
	s.mu.Lock()
	s.sessions[userID] = session
	s.mu.Unlock()
}

func (s *inMemoryWebAuthnSessionRepository) Get(ctx context.Context, userID string) (webauthn.SessionData, bool) {
	s.mu.RLock()
	session, ok := s.sessions[userID]
	s.mu.RUnlock()
	return session, ok
}

func (s *inMemoryWebAuthnSessionRepository) Delete(ctx context.Context, userID string) {
	s.mu.Lock()
	delete(s.sessions, userID)
	s.mu.Unlock()
}
