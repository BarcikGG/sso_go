package httpapi

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/service"
)

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !s.allowAttempt(r, "register-ip", s.clientIP(r), 15, time.Hour) || !s.allowAttempt(r, "register-email", email, 4, time.Hour) {
		problem(w, 429, "too many attempts")
		return
	}
	err := s.identity.Register(r.Context(), service.Registration{Email: email, Login: r.FormValue("login"), GivenName: r.FormValue("given_name"), FamilyName: r.FormValue("family_name"), Name: r.FormValue("name"), Password: r.FormValue("password")})
	if errors.Is(err, service.ErrInvalidInput) {
		problem(w, 400, "invalid registration")
		return
	}
	if err != nil && !errors.Is(err, service.ErrConflict) {
		log.Printf("registration: %v", err)
		problem(w, 502, "registration unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Если заявка создана, письмо с подтверждением отправлено."})
}

func (s *Server) resend(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !s.allowAttempt(r, "resend-ip", s.clientIP(r), 20, time.Hour) || !s.allowAttempt(r, "resend-email", email, 4, time.Hour) {
		problem(w, 429, "too many attempts")
		return
	}
	if err := s.identity.ResendVerification(r.Context(), email); err != nil {
		log.Printf("resend verification: %v", err)
		problem(w, 502, "verification email unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Если аккаунт ожидает подтверждения, ссылка отправлена."})
}

func (s *Server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if err := s.identity.VerifyEmail(r.Context(), r.URL.Query().Get("token")); err != nil {
		http.Redirect(w, r, "/login?notice=invalid_link", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login?notice=verified", http.StatusSeeOther)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	identifier := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
	if !s.allowAttempt(r, "login-id", identifier, 20, 15*time.Minute) || !s.allowAttempt(r, "login-ip", s.clientIP(r), 100, 15*time.Minute) {
		problem(w, 429, "too many attempts")
		return
	}
	token := random()
	status, err := s.identity.Login(r.Context(), identifier, r.FormValue("password"), token)
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		problem(w, 401, "invalid credentials")
		return
	case errors.Is(err, service.ErrUnverified):
		problem(w, 403, "email unverified")
		return
	case errors.Is(err, service.ErrDisabled):
		problem(w, 403, "account disabled")
		return
	case err != nil:
		problem(w, 503, "session unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 604800})
	next := safeNext(r.FormValue("next"))
	if status != "active" {
		next = "/projects"
	}
	jsonResponse(w, 200, map[string]string{"next": next})
}

func safeNext(next string) string {
	if next == "/projects" || next == "/admin" || next == "/settings/profile" || next == "/settings/password" || strings.HasPrefix(next, "/authorize?") && !strings.ContainsAny(next, "\\\r\n") {
		return next
	}
	return "/projects"
}

func (s *Server) session(r *http.Request) (string, error) {
	c, err := r.Cookie("__Host-sso")
	if err != nil {
		return "", err
	}
	return s.identity.Session(r.Context(), c.Value)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	if c, err := r.Cookie("__Host-sso"); err == nil {
		_ = s.identity.Logout(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso", Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	jsonResponse(w, 200, map[string]string{"next": "/login"})
}

func (s *Server) requestAccess(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return
	}
	id, err := s.session(r)
	if err != nil {
		problem(w, 401, "sign in required")
		return
	}
	err = s.identity.RequestAccess(r.Context(), id, r.FormValue("project"))
	if errors.Is(err, service.ErrUnverified) {
		problem(w, 403, "email not verified")
		return
	}
	if errors.Is(err, service.ErrNotFound) {
		problem(w, 400, "unknown project")
		return
	}
	if err != nil {
		problem(w, 503, "access request unavailable")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Заявка отправлена."})
}
