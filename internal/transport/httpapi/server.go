package httpapi

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/endl/sso_go/internal/security"
	"github.com/endl/sso_go/internal/service"
	"github.com/ory/fosite"
)

type Server struct {
	issuer         string
	system         service.System
	syncService    service.Sync
	adminService   service.Admin
	identity       service.Identity
	oidc           service.OAuth
	limits         service.Limits
	trustedProxies []*net.IPNet
	oauth          *fosite.Fosite
}

type Dependencies struct {
	Issuer            string
	OIDCProvider      *fosite.Fosite
	System            service.System
	Identity          service.Identity
	Admin             service.Admin
	Sync              service.Sync
	OAuth             service.OAuth
	Limits            service.Limits
	TrustedProxyCIDRs string
}

func New(d Dependencies) (*Server, error) {
	proxies, err := parseTrustedProxies(d.TrustedProxyCIDRs)
	if err != nil {
		return nil, err
	}
	return &Server{issuer: d.Issuer, system: d.System, identity: d.Identity, adminService: d.Admin, syncService: d.Sync, oidc: d.OAuth, limits: d.Limits, trustedProxies: proxies, oauth: d.OIDCProvider}, nil
}
func random() string { return security.RandomToken() }
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	m.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.system.Ready(r.Context()); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready"))
	})
	m.HandleFunc("GET /metrics", s.metrics)
	m.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	m.HandleFunc("GET /.well-known/jwks.json", s.jwks)
	m.HandleFunc("GET /authorize", s.authorize)
	m.HandleFunc("POST /token", s.token)
	m.HandleFunc("GET /userinfo", s.userinfo)
	m.HandleFunc("GET /sync/snapshot", s.syncSnapshot)
	m.HandleFunc("GET /sync/changes", s.syncChanges)
	m.HandleFunc("GET /api/ui/state", s.uiState)
	m.HandleFunc("POST /api/register", s.register)
	m.HandleFunc("POST /api/verify/resend", s.resend)
	m.HandleFunc("GET /verify", s.verifyEmail)
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("POST /api/access/request", s.requestAccess)
	m.HandleFunc("POST /api/admin/accounts/activate", s.adminActivate)
	m.HandleFunc("POST /api/admin/accounts/disable", s.adminDisable)
	m.HandleFunc("POST /api/admin/access/grant", s.adminGrant)
	m.HandleFunc("POST /api/admin/access/revoke", s.adminRevoke)
	m.HandleFunc("POST /api/password/forgot", s.forgot)
	m.HandleFunc("POST /api/password/reset", s.reset)
	m.HandleFunc("POST /api/settings/password", s.changePassword)
	m.HandleFunc("POST /api/settings/profile", s.updateProfilePage)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
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
	keys, err := s.oidc.JWKS(r.Context())
	if err != nil {
		problem(w, 500, "keys unavailable")
		return
	}
	jsonResponse(w, 200, keys)
}
