package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/endl/sso_go/internal/auth"
)

type AuthStore struct {
	mu                 sync.RWMutex
	usersByID          map[string]auth.User
	userIDByLogin      map[string]string
	clientsByID        map[string]auth.Client
	clientIDByAudience map[string]string
	sessionsByID       map[string]auth.Session
	sessionByHash      map[string]string
	auditEvents        []auth.AuditEvent
}

func NewAuthStore() *AuthStore {
	return &AuthStore{
		usersByID:          make(map[string]auth.User),
		userIDByLogin:      make(map[string]string),
		clientsByID:        make(map[string]auth.Client),
		clientIDByAudience: make(map[string]string),
		sessionsByID:       make(map[string]auth.Session),
		sessionByHash:      make(map[string]string),
	}
}

func (s *AuthStore) SaveUser(_ context.Context, user auth.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, ok := s.userIDByLogin[normalizeLogin(user.Email)]; ok && existingID != user.ID {
		return fmt.Errorf("user email already exists")
	}
	if existingID, ok := s.userIDByLogin[normalizeLogin(user.Username)]; ok && existingID != user.ID {
		return fmt.Errorf("username already exists")
	}

	s.usersByID[user.ID] = user
	s.userIDByLogin[normalizeLogin(user.Email)] = user.ID
	s.userIDByLogin[normalizeLogin(user.Username)] = user.ID

	return nil
}

func (s *AuthStore) FindUserByLogin(_ context.Context, login string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.userIDByLogin[normalizeLogin(login)]
	if !ok {
		return auth.User{}, fmt.Errorf("user not found")
	}

	user, ok := s.usersByID[id]
	if !ok {
		return auth.User{}, fmt.Errorf("user not found")
	}

	return user, nil
}

func (s *AuthStore) FindUserByID(_ context.Context, id string) (auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.usersByID[id]
	if !ok {
		return auth.User{}, fmt.Errorf("user not found")
	}

	return user, nil
}

func (s *AuthStore) ListUsers(_ context.Context) ([]auth.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]auth.User, 0, len(s.usersByID))
	for _, user := range s.usersByID {
		out = append(out, user)
	}

	slices.SortFunc(out, func(a, b auth.User) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
		return 0
	})

	return out, nil
}

func (s *AuthStore) SaveClient(_ context.Context, client auth.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, ok := s.clientIDByAudience[normalizeLogin(client.Audience)]; ok && existingID != client.ID {
		return fmt.Errorf("client audience already exists")
	}

	s.clientsByID[client.ID] = client
	s.clientIDByAudience[normalizeLogin(client.Audience)] = client.ID
	return nil
}

func (s *AuthStore) FindClientByID(_ context.Context, id string) (auth.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, ok := s.clientsByID[id]
	if !ok {
		return auth.Client{}, fmt.Errorf("client not found")
	}
	return client, nil
}

func (s *AuthStore) FindClientByAudience(_ context.Context, audience string) (auth.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, ok := s.clientIDByAudience[normalizeLogin(audience)]
	if !ok {
		return auth.Client{}, fmt.Errorf("client not found")
	}
	client, ok := s.clientsByID[id]
	if !ok {
		return auth.Client{}, fmt.Errorf("client not found")
	}
	return client, nil
}

func (s *AuthStore) ListClients(_ context.Context) ([]auth.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]auth.Client, 0, len(s.clientsByID))
	for _, client := range s.clientsByID {
		out = append(out, client)
	}

	slices.SortFunc(out, func(a, b auth.Client) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return -1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return 1
		}
		return 0
	})

	return out, nil
}

func (s *AuthStore) SaveSession(_ context.Context, session auth.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessionsByID[session.ID] = session
	s.sessionByHash[session.RefreshTokenHash] = session.ID

	return nil
}

func (s *AuthStore) FindSessionByRefreshTokenHash(_ context.Context, hash string) (auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessionID, ok := s.sessionByHash[hash]
	if !ok {
		return auth.Session{}, fmt.Errorf("session not found")
	}

	session, ok := s.sessionsByID[sessionID]
	if !ok {
		return auth.Session{}, fmt.Errorf("session not found")
	}

	return session, nil
}

func (s *AuthStore) FindSessionByID(_ context.Context, id string) (auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, ok := s.sessionsByID[id]
	if !ok {
		return auth.Session{}, fmt.Errorf("session not found")
	}

	return session, nil
}

func (s *AuthStore) ListSessionsByUserID(_ context.Context, userID string) ([]auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]auth.Session, 0)
	for _, session := range s.sessionsByID {
		if session.UserID == userID {
			out = append(out, session)
		}
	}

	slices.SortFunc(out, func(a, b auth.Session) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return 1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 0
	})

	return out, nil
}

func (s *AuthStore) ListSessions(_ context.Context) ([]auth.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]auth.Session, 0, len(s.sessionsByID))
	for _, session := range s.sessionsByID {
		out = append(out, session)
	}

	slices.SortFunc(out, func(a, b auth.Session) int {
		if a.CreatedAt.Before(b.CreatedAt) {
			return 1
		}
		if a.CreatedAt.After(b.CreatedAt) {
			return -1
		}
		return 0
	})

	return out, nil
}

func (s *AuthStore) RevokeSession(_ context.Context, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	session, ok := s.sessionsByID[sessionID]
	if !ok {
		return fmt.Errorf("session not found")
	}

	now := time.Now().UTC()
	session.RevokedAt = &now
	s.sessionsByID[sessionID] = session

	return nil
}

func (s *AuthStore) RevokeAllSessionsByUserID(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for id, session := range s.sessionsByID {
		if session.UserID != userID {
			continue
		}
		session.RevokedAt = &now
		s.sessionsByID[id] = session
	}

	return nil
}

func normalizeLogin(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *AuthStore) RecordAuditEvent(_ context.Context, event auth.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.auditEvents = append(s.auditEvents, event)
	return nil
}
