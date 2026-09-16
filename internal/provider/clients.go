package provider

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/endl/sso_go/internal/store/postgres"
)

func (s *Server) bootstrap(ctx context.Context) error {
	project := os.Getenv("SSO_BOOTSTRAP_PROJECT")
	if project == "" {
		project = "main_api"
	}
	if _, err := s.DB.Pool.Exec(ctx, "INSERT INTO projects(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING", project); err != nil {
		return err
	}
	clientID := os.Getenv("SSO_BOOTSTRAP_CLIENT_ID")
	secret := os.Getenv("SSO_BOOTSTRAP_CLIENT_SECRET")
	redirect := os.Getenv("SSO_BOOTSTRAP_REDIRECT_URI")
	if clientID != "" && secret != "" && redirect != "" {
		if err := validateRedirects([]string{redirect}); err != nil {
			return fmt.Errorf("bootstrap redirect: %w", err)
		}
		_, err := s.DB.Pool.Exec(ctx, "INSERT INTO oidc_clients(id,project_id,secret_hash,redirect_uris) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING", clientID, project, postgres.Hash(secret), []string{redirect})
		if err != nil {
			return err
		}
	}
	email := strings.ToLower(os.Getenv("SSO_BOOTSTRAP_ADMIN_EMAIL"))
	password := os.Getenv("SSO_BOOTSTRAP_ADMIN_PASSWORD")
	if email != "" && password != "" {
		id := random()
		pwd, err := s.passwords.Hash(password)
		if err != nil {
			return err
		}
		_, err = s.DB.Pool.Exec(ctx, "INSERT INTO accounts(id,email,password_hash,name,email_verified_at) VALUES($1,$2,$3,'Administrator',now()) ON CONFLICT(email) DO NOTHING", id, email, pwd)
		if err != nil {
			return err
		}
		_, err = s.DB.Pool.Exec(ctx, "INSERT INTO project_access(account_id,project_id,roles) SELECT id,$1,ARRAY['admin'] FROM accounts WHERE email=$2 ON CONFLICT DO NOTHING", project, email)
		return err
	}
	return nil
}
func (s *Server) RegisterClient(ctx context.Context, id, project, secret string, redirects []string) error {
	if id == "" || project == "" || len(secret) < 24 || len(redirects) == 0 {
		return errors.New("client ID, project, secret of at least 24 characters, and redirect URIs required")
	}
	if err := validateRedirects(redirects); err != nil {
		return err
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO projects(id,name) VALUES($1,$1) ON CONFLICT DO NOTHING", project); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO oidc_clients(id,project_id,secret_hash,redirect_uris) VALUES($1,$2,$3,$4)", id, project, postgres.Hash(secret), redirects); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// GrantProjectAdmin is an operator-only bootstrap action for a verified account.
// It is intentionally unavailable through the public HTTP API.
func (s *Server) GrantProjectAdmin(ctx context.Context, project, email string) error {
	if project == "" || email == "" {
		return errors.New("project and email are required")
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var user string
	err = tx.QueryRow(ctx, "SELECT id FROM accounts WHERE email=$1 AND email_verified_at IS NOT NULL", strings.ToLower(strings.TrimSpace(email))).Scan(&user)
	if err != nil {
		return fmt.Errorf("verified account not found: %w", err)
	}
	var roles []string
	err = tx.QueryRow(ctx, "INSERT INTO project_access(account_id,project_id,roles) VALUES($1,$2,ARRAY['admin']::text[]) ON CONFLICT(account_id,project_id) DO UPDATE SET roles=CASE WHEN 'admin'=ANY(project_access.roles) THEN project_access.roles ELSE array_append(project_access.roles,'admin') END RETURNING roles", user, project).Scan(&roles)
	if err != nil {
		return err
	}
	if err = s.auditOutbox(ctx, tx, "operator", "sso-cli", project, "access.granted", user, map[string]any{"user_id": user, "roles": roles}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func validateRedirects(redirects []string) error {
	if len(redirects) == 0 {
		return errors.New("redirect URI required")
	}
	seen := map[string]bool{}
	for _, raw := range redirects {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil || seen[raw] || strings.Contains(raw, "*") {
			return errors.New("invalid or duplicate redirect URI")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")) {
			return errors.New("redirect URI must use HTTPS outside loopback")
		}
		seen[raw] = true
	}
	return nil
}
