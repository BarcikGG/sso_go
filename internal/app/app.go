// Package app wires repositories, services, transports and background workers.
package app

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/config"
	"github.com/endl/sso_go/internal/events"
	"github.com/endl/sso_go/internal/mail"
	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/security"
	"github.com/endl/sso_go/internal/service"
	"github.com/endl/sso_go/internal/token"
	"github.com/endl/sso_go/internal/transport/grpcapi"
	"github.com/endl/sso_go/internal/transport/httpapi"
	"github.com/ory/fosite"
)

type App struct {
	DB       *postgres.DB
	Keys     *token.KeySet
	HTTP     *httpapi.Server
	GRPC     *grpcapi.Server
	Operator service.Operator
}

func New(ctx context.Context, cfg config.Config) (*App, error) {
	if _, err := url.ParseRequestURI(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("SSO_ISSUER: %w", err)
	}
	db, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*App, error) { db.Pool.Close(); return nil, err }
	issuer := strings.TrimRight(cfg.Issuer, "/")
	keys := token.New(db, issuer)
	if err = keys.Ensure(ctx); err != nil {
		return closeOnError(err)
	}
	passwords := security.NewPasswordHasher()
	operator := service.Operator{Repo: db, Passwords: passwords}
	if err = operator.Bootstrap(ctx, service.Bootstrap{Project: os.Getenv("SSO_BOOTSTRAP_PROJECT"), ClientID: os.Getenv("SSO_BOOTSTRAP_CLIENT_ID"), ClientSecret: os.Getenv("SSO_BOOTSTRAP_CLIENT_SECRET"), Redirect: os.Getenv("SSO_BOOTSTRAP_REDIRECT_URI"), AdminEmail: os.Getenv("SSO_BOOTSTRAP_ADMIN_EMAIL"), AdminPassword: os.Getenv("SSO_BOOTSTRAP_ADMIN_PASSWORD")}); err != nil {
		return closeOnError(err)
	}
	identity := service.Identity{Repo: db, Passwords: passwords, Issuer: issuer, Mailer: mail.SMTP{Addr: os.Getenv("SSO_SMTP_ADDR"), From: os.Getenv("SSO_SMTP_FROM"), Mode: os.Getenv("SSO_SMTP_MODE"), User: os.Getenv("SSO_SMTP_USER"), Password: os.Getenv("SSO_SMTP_PASSWORD")}}
	management := service.Management{Repo: db, Keys: keys, Issuer: issuer}
	httpServer, err := httpapi.New(httpapi.Dependencies{Issuer: issuer, OIDCProvider: fosite.NewOAuth2Provider(db, &fosite.Config{EnforcePKCE: true, IDTokenIssuer: issuer}), System: service.System{Repo: db}, Identity: identity, Admin: service.Admin{Repo: db}, Sync: service.Sync{Repo: db}, OAuth: service.OAuth{Repo: db, Keys: keys, Issuer: issuer}, Limits: service.Limits{Repo: db}, TrustedProxyCIDRs: os.Getenv("SSO_TRUSTED_PROXY_CIDRS")})
	if err != nil {
		return closeOnError(err)
	}
	return &App{DB: db, Keys: keys, HTTP: httpServer, GRPC: grpcapi.New(management), Operator: operator}, nil
}

func (a *App) RotateKey(ctx context.Context) error { return a.Keys.Rotate(ctx) }
func (a *App) RegisterClient(ctx context.Context, id, project, secret string, redirects []string) error {
	return a.Operator.RegisterClient(ctx, id, project, secret, redirects)
}
func (a *App) GrantProjectAdmin(ctx context.Context, project, email string) error {
	return a.Operator.GrantProjectAdmin(ctx, project, email)
}
func (a *App) GrantGlobalAdmin(ctx context.Context, email string) error {
	return a.Operator.GrantGlobalAdmin(ctx, email)
}
func (a *App) PublishOutbox(ctx context.Context, broker, topic string) {
	events.PublishOutbox(ctx, a.DB, broker, topic)
}

func (a *App) Cleanup(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := a.DB.CleanupExpired(ctx); err != nil {
			log.Printf("cleanup: %v", err)
		}
	}
}
