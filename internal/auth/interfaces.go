package auth

import (
	"context"
	"time"
)

type UserStore interface {
	SaveUser(ctx context.Context, user User) error
	FindUserByLogin(ctx context.Context, login string) (User, error)
	FindUserByID(ctx context.Context, id string) (User, error)
	ListUsers(ctx context.Context) ([]User, error)
}

type SessionStore interface {
	SaveSession(ctx context.Context, session Session) error
	FindSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error)
	FindSessionByID(ctx context.Context, id string) (Session, error)
	ListSessionsByUserID(ctx context.Context, userID string) ([]Session, error)
	ListSessions(ctx context.Context) ([]Session, error)
	MarkSessionUsed(ctx context.Context, sessionID string, usedAt time.Time, replacedBySessionID string) error
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeSessionFamily(ctx context.Context, familyID string) error
	RevokeAllSessionsByUserID(ctx context.Context, userID string) error
}

type ClientStore interface {
	SaveClient(ctx context.Context, client Client) error
	FindClientByID(ctx context.Context, id string) (Client, error)
	FindClientByAudience(ctx context.Context, audience string) (Client, error)
	ListClients(ctx context.Context) ([]Client, error)
}
