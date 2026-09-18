package httpapi

import (
	"errors"
	"net/http"

	"github.com/endl/sso_go/internal/service"
)

func (s *Server) globalAdmin(r *http.Request) (string, bool) {
	id, err := s.session(r)
	if err != nil {
		return "", false
	}
	return id, s.adminService.Authorized(r.Context(), id)
}

func (s *Server) adminActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	if err := r.ParseForm(); err != nil || !validCSRF(r) {
		problem(w, 403, "invalid form token")
		return "", false
	}
	id, ok := s.globalAdmin(r)
	if !ok {
		problem(w, 403, "global administrator required")
	}
	return id, ok
}

func (s *Server) adminActivate(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}
	err := s.adminService.Activate(r.Context(), actor, r.FormValue("user_id"))
	if errors.Is(err, service.ErrNotFound) {
		problem(w, 400, "verified pending account required")
		return
	}
	if err != nil {
		problem(w, 500, "update failed")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Аккаунт активирован."})
}

func (s *Server) adminDisable(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}
	err := s.adminService.Disable(r.Context(), actor, r.FormValue("user_id"))
	if errors.Is(err, service.ErrNotFound) || err != nil && err.Error() == "cannot disable own account" {
		problem(w, 400, "account not found or protected")
		return
	}
	if err != nil {
		problem(w, 500, "update failed")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Аккаунт отключён."})
}

func (s *Server) adminGrant(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}
	err := s.adminService.Grant(r.Context(), actor, r.FormValue("user_id"), r.FormValue("project_id"), r.FormValue("roles"))
	if errors.Is(err, service.ErrNotFound) {
		problem(w, 400, "active verified account required")
		return
	}
	if err != nil {
		problem(w, 400, "invalid access grant")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Доступ сохранён."})
}

func (s *Server) adminRevoke(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.adminActor(w, r)
	if !ok {
		return
	}
	err := s.adminService.Revoke(r.Context(), actor, r.FormValue("user_id"), r.FormValue("project_id"))
	if errors.Is(err, service.ErrNotFound) {
		problem(w, 404, "access not found")
		return
	}
	if err != nil {
		problem(w, 500, "update failed")
		return
	}
	jsonResponse(w, 200, map[string]string{"message": "Доступ отозван."})
}
