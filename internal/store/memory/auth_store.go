package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/endl/sso_go/internal/auth"
)

type AuthStore struct {
	mu            sync.RWMutex
	usersByID     map[string]auth.User
	userIDByLogin map[string]string
	sessionsByID  map[string]auth.Session
	sessionByHash map[string]string
}

func NewAuthStore() *AuthStore {
	return &AuthStore{
		usersByID:     make(map[string]auth.User),
		userIDByLogin: make(map[string]string),
		sessionsByID:  make(map[string]auth.Session),
		sessionByHash: make(map[string]string),
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
