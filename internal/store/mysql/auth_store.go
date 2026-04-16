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

	if cfg.AutoMigrate {
		if err := runMigrations(ctx, db); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("run mysql migrations: %w", err)
		}
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

func (s *AuthStore) ListUsers(ctx context.Context) ([]auth.User, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, email, username, password_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM users
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, fmt.Errorf("query users: %w", err)
	}
	defer rows.Close()

	var users []auth.User
	for rows.Next() {
		var (
			user            auth.User
			rolesJSON       []byte
			permissionsJSON []byte
		)

		if err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.Username,
			&user.PasswordHash,
			&user.IsActive,
			&rolesJSON,
			&permissionsJSON,
			&user.CreatedAt,
			&user.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}

		if err := json.Unmarshal(rolesJSON, &user.Roles); err != nil {
			return nil, fmt.Errorf("unmarshal roles: %w", err)
		}
		if err := json.Unmarshal(permissionsJSON, &user.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshal permissions: %w", err)
		}

		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate users: %w", err)
	}

	return users, nil
}

func (s *AuthStore) SaveClient(ctx context.Context, client auth.Client) error {
	rolesJSON, err := json.Marshal(client.Roles)
	if err != nil {
		return fmt.Errorf("marshal client roles: %w", err)
	}
	permissionsJSON, err := json.Marshal(client.Permissions)
	if err != nil {
		return fmt.Errorf("marshal client permissions: %w", err)
	}

	query := `
INSERT INTO clients (
    id, name, audience, secret_hash, is_active, roles_json, permissions_json, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    name = VALUES(name),
    audience = VALUES(audience),
    secret_hash = VALUES(secret_hash),
    is_active = VALUES(is_active),
    roles_json = VALUES(roles_json),
    permissions_json = VALUES(permissions_json),
    updated_at = VALUES(updated_at)
`
	_, err = s.db.ExecContext(ctx, query, client.ID, client.Name, client.Audience, client.SecretHash, client.IsActive, rolesJSON, permissionsJSON, client.CreatedAt.UTC(), client.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("save client: %w", err)
	}
	return nil
}

func (s *AuthStore) FindClientByID(ctx context.Context, id string) (auth.Client, error) {
	query := `
SELECT id, name, audience, secret_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM clients
WHERE id = ?
LIMIT 1
`
	return s.scanClient(ctx, query, id)
}

func (s *AuthStore) FindClientByAudience(ctx context.Context, audience string) (auth.Client, error) {
	query := `
SELECT id, name, audience, secret_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM clients
WHERE audience = ?
LIMIT 1
`
	return s.scanClient(ctx, query, audience)
}

func (s *AuthStore) ListClients(ctx context.Context) ([]auth.Client, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, audience, secret_hash, is_active, roles_json, permissions_json, created_at, updated_at
FROM clients
ORDER BY created_at ASC
`)
	if err != nil {
		return nil, fmt.Errorf("query clients: %w", err)
	}
	defer rows.Close()

	var clients []auth.Client
	for rows.Next() {
		client, err := s.scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, client)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate clients: %w", err)
	}
	return clients, nil
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

func (s *AuthStore) ListSessionsByUserID(ctx context.Context, userID string) ([]auth.Session, error) {
	query := `
SELECT id, user_id, refresh_token_hash, created_at, expires_at, revoked_at
FROM sessions
WHERE user_id = ?
ORDER BY created_at DESC
`

	return s.scanSessions(ctx, query, userID)
}

func (s *AuthStore) ListSessions(ctx context.Context) ([]auth.Session, error) {
	query := `
SELECT id, user_id, refresh_token_hash, created_at, expires_at, revoked_at
FROM sessions
ORDER BY created_at DESC
`

	return s.scanSessions(ctx, query)
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

func (s *AuthStore) scanClient(ctx context.Context, query string, args ...any) (auth.Client, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return auth.Client{}, fmt.Errorf("query client: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return auth.Client{}, fmt.Errorf("client not found")
	}
	return s.scanClientRow(rows)
}

func (s *AuthStore) scanClientRow(scanner interface{ Scan(dest ...any) error }) (auth.Client, error) {
	var (
		client          auth.Client
		rolesJSON       []byte
		permissionsJSON []byte
	)
	if err := scanner.Scan(
		&client.ID,
		&client.Name,
		&client.Audience,
		&client.SecretHash,
		&client.IsActive,
		&rolesJSON,
		&permissionsJSON,
		&client.CreatedAt,
		&client.UpdatedAt,
	); err != nil {
		return auth.Client{}, fmt.Errorf("scan client: %w", err)
	}
	if err := json.Unmarshal(rolesJSON, &client.Roles); err != nil {
		return auth.Client{}, fmt.Errorf("unmarshal client roles: %w", err)
	}
	if err := json.Unmarshal(permissionsJSON, &client.Permissions); err != nil {
		return auth.Client{}, fmt.Errorf("unmarshal client permissions: %w", err)
	}
	return client, nil
}

func normalizeLogin(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (s *AuthStore) RecordAuditEvent(ctx context.Context, event auth.AuditEvent) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = s.db.ExecContext(
		ctx,
		`INSERT INTO audit_events (id, user_id, event_type, metadata_json, created_at) VALUES (?, NULLIF(?, ''), ?, ?, ?)`,
		event.ID,
		event.UserID,
		event.EventType,
		metadataJSON,
		event.CreatedAt.UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}

func (s *AuthStore) scanSessions(ctx context.Context, query string, args ...any) ([]auth.Session, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []auth.Session
	for rows.Next() {
		var (
			session   auth.Session
			revokedAt sql.NullTime
		)

		if err := rows.Scan(
			&session.ID,
			&session.UserID,
			&session.RefreshTokenHash,
			&session.CreatedAt,
			&session.ExpiresAt,
			&revokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}

		if revokedAt.Valid {
			t := revokedAt.Time.UTC()
			session.RevokedAt = &t
		}

		sessions = append(sessions, session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}

	return sessions, nil
}
