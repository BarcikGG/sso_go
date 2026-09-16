// Package config reads and validates the process-level SSO settings.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	DatabaseURL string
	Issuer      string
	HTTPPort    string
	GRPCPort    string
	KafkaBroker string
	KafkaTopic  string
	RotateKey   bool
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL: os.Getenv("SSO_DATABASE_URL"),
		Issuer:      strings.TrimRight(getenv("SSO_ISSUER", "http://localhost:8080"), "/"),
		HTTPPort:    getenv("SSO_HTTP_PORT", "8080"),
		GRPCPort:    getenv("SSO_GRPC_PORT", "9090"),
		KafkaBroker: os.Getenv("KAFKA_BROKER"),
		KafkaTopic:  "sso.events",
		RotateKey:   os.Getenv("SSO_ROTATE_KEY_ON_START") == "1",
	}
	if c.DatabaseURL == "" {
		return c, errors.New("SSO_DATABASE_URL is required")
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return c, errors.New("SSO_ISSUER must be an HTTP(S) origin without credentials, path, query or fragment")
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return c, errors.New("SSO_ISSUER must use HTTPS outside localhost")
	}
	for name, port := range map[string]string{"SSO_HTTP_PORT": c.HTTPPort, "SSO_GRPC_PORT": c.GRPCPort} {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return c, fmt.Errorf("invalid %s: expected port number from 1 to 65535", name)
		}
	}
	if (os.Getenv("SSO_GRPC_TLS_CERT") == "") != (os.Getenv("SSO_GRPC_TLS_KEY") == "") {
		return c, errors.New("SSO_GRPC_TLS_CERT and SSO_GRPC_TLS_KEY must be configured together")
	}
	return c, nil
}
