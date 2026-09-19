package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/security"
)

type Operator struct {
	Repo      *postgres.DB
	Passwords *security.PasswordHasher
}

type Bootstrap struct{ Project, ClientID, ClientSecret, Redirect, AdminEmail, AdminPassword string }

func (s Operator) Bootstrap(ctx context.Context, b Bootstrap) error {
	if b.Project == "" {
		b.Project = "main_api"
	}
	if b.ClientID != "" && b.ClientSecret != "" && b.Redirect != "" {
		if err := ValidateRedirects([]string{b.Redirect}); err != nil {
			return fmt.Errorf("bootstrap redirect: %w", err)
		}
	}
	var adminHash string
	if b.AdminEmail != "" && b.AdminPassword != "" {
		var err error
		adminHash, err = s.Passwords.Hash(b.AdminPassword)
		if err != nil {
			return err
		}
	}
	clientHash := ""
	if b.ClientSecret != "" {
		clientHash = postgres.Hash(b.ClientSecret)
	}
	adminID, err := security.NewUUIDv7()
	if err != nil {
		return err
	}
	return s.Repo.EnsureBootstrap(ctx, b.Project, b.ClientID, clientHash, b.Redirect, adminID, strings.ToLower(b.AdminEmail), adminHash)
}

func (s Operator) RegisterClient(ctx context.Context, id, project, secret string, redirects []string) error {
	if id == "" || project == "" || len(secret) < 24 || len(redirects) == 0 {
		return errors.New("client ID, project, secret of at least 24 characters, and redirect URIs required")
	}
	if err := ValidateRedirects(redirects); err != nil {
		return err
	}
	return s.Repo.RegisterClient(ctx, id, project, postgres.Hash(secret), redirects)
}

func (s Operator) GrantProjectAdmin(ctx context.Context, project, email string) error {
	if project == "" || email == "" {
		return errors.New("project and email are required")
	}
	return s.Repo.GrantProjectAdmin(ctx, project, email)
}

func (s Operator) GrantGlobalAdmin(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return errors.New("verified account email is required")
	}
	return s.Repo.GrantGlobalAdmin(ctx, email)
}

func ValidateRedirects(redirects []string) error {
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
