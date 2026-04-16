package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/auth"
	"github.com/endl/sso_go/internal/config"
)

type healthResponse struct {
	Status    string    `json:"status"`
	Service   string    `json:"service"`
	Env       string    `json:"env"`
	Timestamp time.Time `json:"timestamp"`
}

type placeholderResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
	Audience string `json:"audience"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type clientTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}

type revokeSessionRequest struct {
	SessionID string `json:"session_id"`
}

type setUserActiveRequest struct {
	UserID   string `json:"user_id"`
	IsActive bool   `json:"is_active"`
}

type setUserAccessRequest struct {
	UserID      string   `json:"user_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

func healthHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:    "ok",
			Service:   cfg.App.Name,
			Env:       cfg.App.Env,
			Timestamp: time.Now().UTC(),
		})
	}
}

func readyHandler(cfg config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{
			Status:    "ready",
			Service:   cfg.App.Name,
			Env:       cfg.App.Env,
			Timestamp: time.Now().UTC(),
		})
	}
}

func loginHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		pair, err := authService.Login(ctx, auth.LoginInput{
			Login:    req.Login,
			Password: req.Password,
			Audience: req.Audience,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, pair)
	}
}

func refreshHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		pair, err := authService.Refresh(ctx, req.RefreshToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, pair)
	}
}

func clientTokenHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		var req clientTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		pair, err := authService.ClientToken(ctx, auth.ClientTokenInput{
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			Audience:     req.Audience,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, pair)
	}
}

func logoutHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		if err := authService.Logout(ctx, accessToken); err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, placeholderResponse{
			Status:  "ok",
			Message: "session revoked",
		})
	}
}

func logoutAllHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		if err := authService.LogoutAll(ctx, accessToken); err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, placeholderResponse{
			Status:  "ok",
			Message: "all sessions revoked",
		})
	}
}

func meHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		user, err := authService.Me(ctx, accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, user)
	}
}

func mySessionsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		sessions, err := authService.ListMySessions(ctx, accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
	}
}

func createUserHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		var req auth.CreateUserInput
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		user, err := authService.CreateUser(ctx, accessToken, req)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, user)
	}
}

func adminSessionsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		sessions, err := authService.ListSessions(ctx, accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"sessions": sessions})
	}
}

func revokeSessionHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		var req revokeSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		if err := authService.RevokeSessionByID(ctx, accessToken, req.SessionID); err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, placeholderResponse{
			Status:  "ok",
			Message: "session revoked",
		})
	}
}

func listUsersHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		users, err := authService.ListUsers(ctx, accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"users": users})
	}
}

func setUserActiveHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		var req setUserActiveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		user, err := authService.SetUserActive(ctx, accessToken, auth.SetUserActiveInput{
			UserID:   req.UserID,
			IsActive: req.IsActive,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, user)
	}
}

func setUserAccessHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		var req setUserAccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		user, err := authService.SetUserAccess(ctx, accessToken, auth.SetUserAccessInput{
			UserID:      req.UserID,
			Roles:       req.Roles,
			Permissions: req.Permissions,
		})
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, user)
	}
}

func createClientHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		var req auth.CreateClientInput
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		client, err := authService.CreateClient(ctx, accessToken, req)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, client)
	}
}

func listClientsHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := withRequestMetadata(r)
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		clients, err := authService.ListClients(ctx, accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{"clients": clients})
	}
}

func jwksHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		payload, err := authService.JWKSPayload()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal_error", "unable to build jwks"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(payload)
}

func bearerTokenFromRequest(r *http.Request) (string, error) {
	return auth.ExtractBearerToken(r.Header.Get("Authorization"))
}

func writeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		writeJSON(w, http.StatusUnauthorized, errorResponse("invalid_credentials", err.Error()))
	case errors.Is(err, auth.ErrInvalidToken):
		writeJSON(w, http.StatusUnauthorized, errorResponse("invalid_token", err.Error()))
	case errors.Is(err, auth.ErrUnauthorized):
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized", err.Error()))
	case errors.Is(err, auth.ErrForbidden):
		writeJSON(w, http.StatusForbidden, errorResponse("forbidden", err.Error()))
	case errors.Is(err, auth.ErrInvalidInput):
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid_input", err.Error()))
	default:
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal_error", "internal server error"))
	}
}

func errorResponse(code, message string) map[string]string {
	return map[string]string{
		"error":   code,
		"message": message,
	}
}

func withRequestMetadata(r *http.Request) context.Context {
	return auth.WithRequestMetadata(r.Context(), auth.RequestMetadata{
		RequestID: requestIDFromRequest(r),
		ClientIP:  clientIPFromRequest(r),
		UserAgent: strings.TrimSpace(r.UserAgent()),
	})
}

func requestIDFromRequest(r *http.Request) string {
	if value := strings.TrimSpace(r.Header.Get("X-Request-Id")); value != "" {
		return value
	}
	if value := strings.TrimSpace(r.Header.Get("X-Request-ID")); value != "" {
		return value
	}
	return fmtRequestID()
}

func clientIPFromRequest(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-Ip")); realIP != "" {
		return realIP
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}

	host := r.RemoteAddr
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}

func fmtRequestID() string {
	return time.Now().UTC().Format("20060102150405.000000000")
}
