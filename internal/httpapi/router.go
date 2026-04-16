package httpapi

import (
	"net/http"

	"github.com/endl/sso_go/internal/auth"
	"github.com/endl/sso_go/internal/config"
)

func NewRouter(cfg config.Config, authService *auth.Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler(cfg))
	mux.HandleFunc("GET /readyz", readyHandler(cfg))
	mux.HandleFunc("POST /auth/login", loginHandler(authService))
	mux.HandleFunc("POST /auth/refresh", refreshHandler(authService))
	mux.HandleFunc("POST /auth/client-token", clientTokenHandler(authService))
	mux.HandleFunc("POST /auth/logout", logoutHandler(authService))
	mux.HandleFunc("POST /auth/logout-all", logoutAllHandler(authService))
	mux.HandleFunc("GET /auth/me", meHandler(authService))
	mux.HandleFunc("GET /auth/sessions", mySessionsHandler(authService))
	mux.HandleFunc("GET /.well-known/jwks.json", jwksHandler(authService))
	mux.HandleFunc("POST /admin/users", createUserHandler(authService))
	mux.HandleFunc("GET /admin/users", listUsersHandler(authService))
	mux.HandleFunc("POST /admin/users/status", setUserActiveHandler(authService))
	mux.HandleFunc("POST /admin/users/access", setUserAccessHandler(authService))
	mux.HandleFunc("POST /admin/clients", createClientHandler(authService))
	mux.HandleFunc("GET /admin/clients", listClientsHandler(authService))
	mux.HandleFunc("GET /admin/sessions", adminSessionsHandler(authService))
	mux.HandleFunc("POST /admin/sessions/revoke", revokeSessionHandler(authService))

	return mux
}
