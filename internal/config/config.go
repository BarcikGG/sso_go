package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPPort        = 8080
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 24 * time.Hour * 7
)

type Config struct {
	App       AppConfig
	HTTP      HTTPConfig
	Token     TokenConfig
	Database  DatabaseConfig
	Bootstrap BootstrapConfig
}

type AppConfig struct {
	Name string
	Env  string
}

type HTTPConfig struct {
	Port int
}

type TokenConfig struct {
	Issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SigningKey      string
}

type DatabaseConfig struct {
	Driver      string
	URL         string
	AutoMigrate bool
}

type BootstrapConfig struct {
	AdminEmail    string
	AdminUsername string
	AdminPassword string
}

func Load() (Config, error) {
	port, err := intFromEnv("SSO_HTTP_PORT", defaultHTTPPort)
	if err != nil {
		return Config{}, err
	}

	accessTTL, err := durationFromEnv("SSO_ACCESS_TOKEN_TTL", defaultAccessTokenTTL)
	if err != nil {
		return Config{}, err
	}

	refreshTTL, err := durationFromEnv("SSO_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		App: AppConfig{
			Name: stringFromEnv("SSO_APP_NAME", "sso"),
			Env:  stringFromEnv("SSO_ENV", "dev"),
		},
		HTTP: HTTPConfig{
			Port: port,
		},
		Token: TokenConfig{
			Issuer:          stringFromEnv("SSO_ISSUER", "sso.local"),
			AccessTokenTTL:  accessTTL,
			RefreshTokenTTL: refreshTTL,
			SigningKey:      stringFromEnv("SSO_SIGNING_KEY", "local-dev-signing-key-change-me"),
		},
		Database: DatabaseConfig{
			Driver:      stringFromEnv("SSO_DATABASE_DRIVER", "mysql"),
			URL:         stringFromEnv("SSO_DATABASE_URL", ""),
			AutoMigrate: boolFromEnv("SSO_DATABASE_AUTO_MIGRATE", true),
		},
		Bootstrap: BootstrapConfig{
			AdminEmail:    stringFromEnv("SSO_BOOTSTRAP_ADMIN_EMAIL", ""),
			AdminUsername: stringFromEnv("SSO_BOOTSTRAP_ADMIN_USERNAME", ""),
			AdminPassword: stringFromEnv("SSO_BOOTSTRAP_ADMIN_PASSWORD", ""),
		},
	}

	return cfg, nil
}

func stringFromEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func intFromEnv(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: parse int: %w", key, err)
	}

	return value, nil
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: parse duration: %w", key, err)
	}

	return value, nil
}

func boolFromEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
