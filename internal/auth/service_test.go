package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/endl/sso_go/internal/auth"
	"github.com/endl/sso_go/internal/config"
	"github.com/endl/sso_go/internal/store/memory"
)

func TestServiceLoginRefreshAndMe(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Token: config.TokenConfig{
			Issuer:          "test-issuer",
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
			SigningKey:      "test-signing-key",
		},
		Bootstrap: config.BootstrapConfig{
			AdminEmail:    "admin@example.local",
			AdminUsername: "admin",
			AdminPassword: "secret123",
		},
	}

	store := memory.NewAuthStore()
	service, err := auth.NewService(cfg, store, store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if err := service.BootstrapAdmin(context.Background()); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}

	pair, err := service.Login(context.Background(), auth.LoginInput{
		Login:    "admin",
		Password: "secret123",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected non-empty token pair")
	}

	me, err := service.Me(context.Background(), pair.AccessToken)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if me.Username != "admin" {
		t.Fatalf("unexpected username: %s", me.Username)
	}

	refreshed, err := service.Refresh(context.Background(), pair.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		t.Fatal("expected non-empty refreshed token pair")
	}
}

func TestServiceRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		Token: config.TokenConfig{
			Issuer:          "test-issuer",
			AccessTokenTTL:  time.Minute,
			RefreshTokenTTL: time.Hour,
			SigningKey:      "test-signing-key",
		},
		Bootstrap: config.BootstrapConfig{
			AdminPassword: "secret123",
		},
	}

	store := memory.NewAuthStore()
	service, err := auth.NewService(cfg, store, store)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	if err := service.BootstrapAdmin(context.Background()); err != nil {
		t.Fatalf("bootstrap admin: %v", err)
	}

	if _, err := service.Login(context.Background(), auth.LoginInput{
		Login:    "admin",
		Password: "wrong-password",
	}); err == nil {
		t.Fatal("expected login to fail")
	}
}
