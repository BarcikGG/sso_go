package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/service"
)

func (s *Server) forgot(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !s.allowAttempt(r, "forgot-ip", s.clientIP(r), 20, time.Hour) || !s.allowAttempt(r, "forgot-email", email, 4, time.Hour) {
		problem(w, 429, "too many attempts")
		return
	}
	s.identity.ForgotPassword(r.Context(), email)
	jsonResponse(w, 200, map[string]string{"message": "Если аккаунт существует, ссылка для смены пароля отправлена."})
}

func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	err := s.identity.ResetPassword(r.Context(), r.FormValue("token"), r.FormValue("password"))
	if errors.Is(err, service.ErrInvalidInput) {
		problem(w, 400, "invalid password or link")
		return
	}
	if err != nil {
		problem(w, 503, "reset failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	jsonResponse(w, 200, map[string]string{"message": "Пароль изменён. Все прежние сессии завершены."})
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	id, err := s.session(r)
	if err != nil {
		problem(w, 401, "sign in required")
		return
	}
	if !s.allowAttempt(r, "password-change", id, 10, time.Hour) {
		problem(w, 429, "too many attempts")
		return
	}
	err = s.identity.ChangePassword(r.Context(), id, r.FormValue("current_password"), r.FormValue("password"))
	if errors.Is(err, service.ErrInvalidInput) {
		problem(w, 400, "invalid password")
		return
	}
	if errors.Is(err, service.ErrInvalidCredentials) {
		problem(w, 401, "invalid current password")
		return
	}
	if err != nil {
		problem(w, 503, "update failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	jsonResponse(w, 200, map[string]string{"next": "/login?notice=password_changed"})
}

func (s *Server) updateProfilePage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	id, err := s.session(r)
	if err != nil {
		problem(w, 401, "sign in required")
		return
	}
	err = s.identity.UpdateProfile(r.Context(), id, r.FormValue("login"), r.FormValue("given_name"), r.FormValue("family_name"), r.FormValue("avatar_url"))
	if errors.Is(err, service.ErrInvalidInput) {
		problem(w, 400, "invalid profile")
		return
	}
	if errors.Is(err, service.ErrNotFound) || errors.Is(err, service.ErrConflict) {
		problem(w, 409, "login unavailable or account inactive")
		return
	}
	if err != nil {
		problem(w, 503, "profile unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Профиль сохранён."})
}
