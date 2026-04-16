package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/endl/sso_go/internal/auth"
	"github.com/endl/sso_go/internal/config"
)

type AuthStore struct {
	db *sql.DB
}

func New(ctx context.Context, cfg config.DatabaseConfig) (*AuthStore, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("database url is empty")
	}

	db, err := sql.Open("mysql", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("open mysql connection: %w", err)
	}

	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	return &AuthStore{db: db}, nil
}

func (s *AuthStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}

	return s.db.Close()
}

func (s *AuthStore) SaveUser(ctx context.Context, user auth.User) error {
	rolesJSON, err := json.Marshal(user.Roles)
	if err != nil {
		return fmt.Errorf("marshal roles: %w", err)
	}

	permissionsJSON, err := json.Marshal(user.Permissions)
	if err != nil {
		return fmt.Errorf("marshal permissions: %w", err)
	}

	query := `
INSERT INTO users (
    id, email, username, password_hash, is_active, roles_json, permissions_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    email = VALUES(email),
    username = VALUES(username),
    password_hash = VALUES(password_hash),
    is_active = VALUES(is_active),
    roles_json = VALUES(roles_json),
    permissions_json = VALUES(permissions_json),
    updated_at = VALUES(updated_at)
`

	_, err = s.db.ExecContext(
		ctx,
		query,
		user.ID,
		strings.ToLower(strings.TrimSpace(user.Email)),
		strings.TrimSpace(user.Username),
		user.PasswordHash,
		user.IsActive,
		rolesJSON,
		permissionsJSON,
		user.CreatedAt.UTC(),
		user.UpdatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("save user: %w", err)
	}

	return nil
}

func (s *AuthStore) FindUserByLogin(ctx context.Context, login string) (auth.User, error) {
	query := `
SELECT id, email, username, password_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM users
WHERE email = ? OR username = ?
LIMIT 1
`

	return s.scanUser(ctx, query, normalizeLogin(login), strings.TrimSpace(login))
}

func (s *AuthStore) FindUserByID(ctx context.Context, id string) (auth.User, error) {
	query := `
SELECT id, email, username, password_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM users
WHERE id = ?
LIMIT 1
`

	return s.scanUser(ctx, query, id)
}

func (s *AuthStore) SaveSession(ctx context.Context, session auth.Session) error {
	query := `
INSERT INTO sessions (
    id, user_id, refresh_token_hash, created_at, expires_at, revoked_at
) VALUES (?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    refresh_token_hash = VALUES(refresh_token_hash),
    expires_at = VALUES(expires_at),
    revoked_at = VALUES(revoked_at)
`

	_, err := s.db.ExecContext(
		ctx,
		query,
		session.ID,
		session.UserID,
		session.RefreshTokenHash,
		session.CreatedAt.UTC(),
		session.ExpiresAt.UTC(),
		session.RevokedAt,
	)
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	return nil
}

func (s *AuthStore) FindSessionByRefreshTokenHash(ctx context.Context, hash string) (auth.Session, error) {
	query := `
SELECT id, user_id, refresh_token_hash, created_at, expires_at, revoked_at
FROM sessions
WHERE refresh_token_hash = ?
LIMIT 1
`

	return s.scanSession(ctx, query, hash)
}

func (s *AuthStore) FindSessionByID(ctx context.Context, id string) (auth.Session, error) {
	query := `
SELECT id, user_id, refresh_token_hash, created_at, expires_at, revoked_at
FROM sessions
WHERE id = ?
LIMIT 1
`

	return s.scanSession(ctx, query, id)
}

func (s *AuthStore) RevokeSession(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE id = ?`, time.Now().UTC(), sessionID)
	if err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	return nil
}

func (s *AuthStore) RevokeAllSessionsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}

	return nil
}

func (s *AuthStore) scanUser(ctx context.Context, query string, args ...any) (auth.User, error) {
	var (
		user            auth.User
		rolesJSON       []byte
		permissionsJSON []byte
	)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&user.ID,
		&user.Email,
		&user.Username,
		&user.PasswordHash,
		&user.IsActive,
		&rolesJSON,
		&permissionsJSON,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.User{}, fmt.Errorf("user not found")
		}
		return auth.User{}, fmt.Errorf("query user: %w", err)
	}

	if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
		return auth.User{}, fmt.Errorf("unmarshal roles: %w", err)
	}
	if err := json.Unmarshal(permissionsJSON, &user.Permissions); err != nil {
		return auth.User{}, fmt.Errorf("unmarshal permissions: %w", err)
	}

	return user, nil
}

func (s *AuthStore) scanSession(ctx context.Context, query string, args ...any) (auth.Session, error) {
	var (
		session   auth.Session
		revokedAt sql.NullTime
	)

	err := s.db.QueryRowContext(ctx, query, args...).Scan(
		&session.ID,
		&session.UserID,
		&session.RefreshTokenHash,
		&session.CreatedAt,
		&session.ExpiresAt,
		&revokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return auth.Session{}, fmt.Errorf("session not found")
		}
		return auth.Session{}, fmt.Errorf("query session: %w", err)
	}

	if revokedAt.Valid {
		t := revokedAt.Time.UTC()
		session.RevokedAt = &t
	}

	return session, nil
}

func normalizeLogin(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
