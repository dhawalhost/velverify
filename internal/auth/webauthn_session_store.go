package auth

import (
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnSessionStore stores transient WebAuthn session state.
// Implementations can be in-memory (dev) or distributed (Redis) for horizontal scaling.
type WebAuthnSessionStore interface {
	Set(userID string, session webauthn.SessionData)
	Get(userID string) (webauthn.SessionData, bool)
	Delete(userID string)
}

type inMemoryWebAuthnSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]webauthn.SessionData
}

func newInMemoryWebAuthnSessionStore() WebAuthnSessionStore {
	return &inMemoryWebAuthnSessionStore{
		sessions: make(map[string]webauthn.SessionData),
	}
}

func (s *inMemoryWebAuthnSessionStore) Set(userID string, session webauthn.SessionData) {
	s.mu.Lock()
	s.sessions[userID] = session
	s.mu.Unlock()
}

func (s *inMemoryWebAuthnSessionStore) Get(userID string) (webauthn.SessionData, bool) {
	s.mu.RLock()
	session, ok := s.sessions[userID]
	s.mu.RUnlock()
	return session, ok
}

func (s *inMemoryWebAuthnSessionStore) Delete(userID string) {
	s.mu.Lock()
	delete(s.sessions, userID)
	s.mu.Unlock()
}
