package provider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/endl/sso_go/internal/events"
	"github.com/endl/sso_go/internal/security"
	"github.com/endl/sso_go/internal/store/postgres"
	"github.com/endl/sso_go/internal/token"
	"github.com/ory/fosite"
)

type Server struct {
	DB                 *postgres.DB
	keys               *token.KeySet
	issuer             string
	passwords          *security.PasswordHasher
	oauth              *fosite.Fosite
	smtpAddr, smtpFrom string
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func New(ctx context.Context, dsn, issuer string) (*Server, error) {
	if _, err := url.ParseRequestURI(issuer); err != nil {
		return nil, fmt.Errorf("SSO_ISSUER: %w", err)
	}
	db, err := postgres.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	s := &Server{DB: db, keys: token.New(db.Pool, strings.TrimRight(issuer, "/")), issuer: strings.TrimRight(issuer, "/"), passwords: security.NewPasswordHasher(), smtpAddr: os.Getenv("SSO_SMTP_ADDR"), smtpFrom: os.Getenv("SSO_SMTP_FROM")}
	if err = s.keys.Ensure(ctx); err != nil {
		db.Pool.Close()
		return nil, err
	}
	s.oauth = fosite.NewOAuth2Provider(db, &fosite.Config{EnforcePKCE: true, IDTokenIssuer: s.issuer})
	if err = s.bootstrap(ctx); err != nil {
		db.Pool.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) RotateKey(ctx context.Context) error { return s.keys.Rotate(ctx) }

func (s *Server) PublishOutbox(ctx context.Context, broker, topic string) {
	events.PublishOutbox(ctx, s.DB.Pool, broker, topic)
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	m.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	m.HandleFunc("GET /authorize", s.authorize)
	m.HandleFunc("POST /token", s.token)
	m.HandleFunc("GET /userinfo", s.userinfo)
	m.HandleFunc("GET /register", s.registerPage)
	m.HandleFunc("POST /register", s.register)
	m.HandleFunc("GET /verify/resend", s.resendPage)
	m.HandleFunc("POST /verify/resend", s.resend)
	m.HandleFunc("GET /verify", s.verifyEmail)
	m.HandleFunc("GET /login", s.loginPage)
	m.HandleFunc("POST /login", s.login)
	m.HandleFunc("POST /logout", s.logout)
	m.HandleFunc("GET /projects", s.projects)
	m.HandleFunc("POST /access/request", s.requestAccess)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		m.ServeHTTP(w, r)
	})
}
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}
func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, 200, map[string]any{"issuer": s.issuer, "authorization_endpoint": s.issuer + "/authorize", "token_endpoint": s.issuer + "/token", "userinfo_endpoint": s.issuer + "/userinfo", "jwks_uri": s.issuer + "/.well-known/jwks.json", "response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"}})
}
func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	keys, err := s.keys.JWKS(r.Context())
	if err != nil {
		problem(w, 500, "keys unavailable")
		return
	}
	jsonResponse(w, 200, keys)
}
