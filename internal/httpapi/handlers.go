package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
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
		var req loginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		pair, err := authService.Login(r.Context(), auth.LoginInput{
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
		var req refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid_request", "request body must be valid JSON"))
			return
		}

		pair, err := authService.Refresh(r.Context(), req.RefreshToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, pair)
	}
}

func logoutHandler(authService *auth.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		if err := authService.Logout(r.Context(), accessToken); err != nil {
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
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		if err := authService.LogoutAll(r.Context(), accessToken); err != nil {
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
		accessToken, err := bearerTokenFromRequest(r)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		user, err := authService.Me(r.Context(), accessToken)
		if err != nil {
			writeAuthError(w, err)
			return
		}

		writeJSON(w, http.StatusOK, user)
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
