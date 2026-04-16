package auth

import "context"

type UserStore interface {
	SaveUser(ctx context.Context, user User) error
	FindUserByLogin(ctx context.Context, login string) (User, error)
	FindUserByID(ctx context.Context, id string) (User, error)
}

type SessionStore interface {
	SaveSession(ctx context.Context, session Session) error
	FindSessionByRefreshTokenHash(ctx context.Context, hash string) (Session, error)
	FindSessionByID(ctx context.Context, id string) (Session, error)
	RevokeSession(ctx context.Context, sessionID string) error
	RevokeAllSessionsByUserID(ctx context.Context, userID string) error
}
