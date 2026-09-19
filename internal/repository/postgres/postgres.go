// Package postgres owns SSO migrations, queries and transactional persistence.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	migration "github.com/endl/sso_go/migrations/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ory/fosite"
)

type DB struct{ Pool *pgxpool.Pool }

func Open(ctx context.Context, dsn string) (*DB, error) {
	if dsn == "" {
		return nil, errors.New("SSO_DATABASE_URL is required")
	}
	p, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	db := &DB{p}
	if err = db.Migrate(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return db, nil
}

func (d *DB) Migrate(ctx context.Context) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(77213001)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations (version integer PRIMARY KEY)"); err != nil {
		return err
	}
	var version int
	if err = tx.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM schema_migrations").Scan(&version); err != nil {
		return err
	}
	if version > 3 {
		return fmt.Errorf("database migration %d is newer than this binary", version)
	}
	if version == 0 {
		var existing bool
		if err = tx.QueryRow(ctx, "SELECT to_regclass('public.accounts') IS NOT NULL").Scan(&existing); err != nil {
			return err
		}
		if !existing {
			if _, err = tx.Exec(ctx, migration.Initial); err != nil {
				return fmt.Errorf("migration 1: %w", err)
			}
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(1)"); err != nil {
			return err
		}
		version = 1
	}
	if version == 1 {
		if _, err = tx.Exec(ctx, migration.Identity); err != nil {
			return fmt.Errorf("migration 2: %w", err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(2)"); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if _, err = tx.Exec(ctx, migration.LegacyIDs); err != nil {
			return fmt.Errorf("migration 3: %w", err)
		}
		if _, err = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES(3)"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func Hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }

type Client struct {
	ID, Project, SecretHash string
	Redirects               []string
}

func (d *DB) Client(ctx context.Context, id string) (Client, error) {
	var c Client
	err := d.Pool.QueryRow(ctx, "SELECT id,project_id,secret_hash,redirect_uris FROM oidc_clients WHERE id=$1", id).Scan(&c.ID, &c.Project, &c.SecretHash, &c.Redirects)
	return c, err
}

// GetClient lets Fosite validate registered redirect URIs and OAuth client metadata.
func (d *DB) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	c, err := d.Client(ctx, id)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return &fosite.DefaultClient{ID: c.ID, RedirectURIs: c.Redirects, GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, Scopes: []string{"openid", "profile", "email", "offline_access"}, Audience: []string{c.Project}}, nil
}

func (d *DB) ClientAssertionJWTValid(context.Context, string) error { return fosite.ErrInvalidClient }
func (d *DB) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return fosite.ErrInvalidClient
}

type Account struct {
	ID, Email, Login, PasswordHash, Name, GivenName, FamilyName, Avatar, Status string
	Verified                                                                    *time.Time
	GlobalAdmin                                                                 bool
}

func (d *DB) Account(ctx context.Context, id string) (Account, error) {
	var a Account
	err := d.Pool.QueryRow(ctx, "SELECT id,email,login,password_hash,name,given_name,family_name,avatar_url,status,email_verified_at,is_global_admin FROM accounts WHERE id=$1", id).Scan(&a.ID, &a.Email, &a.Login, &a.PasswordHash, &a.Name, &a.GivenName, &a.FamilyName, &a.Avatar, &a.Status, &a.Verified, &a.GlobalAdmin)
	return a, err
}
func (d *DB) Access(ctx context.Context, user, project string) ([]string, error) {
	var roles []string
	err := d.Pool.QueryRow(ctx, "SELECT roles FROM project_access WHERE account_id=$1 AND project_id=$2", user, project).Scan(&roles)
	return roles, err
}
