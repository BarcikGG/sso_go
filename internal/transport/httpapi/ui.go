package httpapi

import (
	"crypto/subtle"
	"net/http"
)

func formCSRF(w http.ResponseWriter) string {
	token := random()
	http.SetCookie(w, &http.Cookie{Name: "__Host-sso-form", Value: token, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	return token
}

func validCSRF(r *http.Request) bool {
	c, err := r.Cookie("__Host-sso-form")
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("csrf"))) == 1
}

func (s *Server) uiState(w http.ResponseWriter, r *http.Request) {
	state := map[string]any{"csrf": formCSRF(w)}
	id, err := s.session(r)
	if err == nil {
		account, err := s.identity.Account(r.Context(), id)
		if err != nil {
			problem(w, 503, "account unavailable")
			return
		}
		state["account"] = map[string]any{"id": account.ID, "email": account.Email, "login": account.Login, "name": account.Name, "given_name": account.GivenName, "family_name": account.FamilyName, "avatar_url": account.Avatar, "status": account.Status, "global_admin": account.GlobalAdmin}
		projects, err := s.identity.Projects(r.Context(), id)
		if err != nil {
			problem(w, 503, "projects unavailable")
			return
		}
		state["projects"] = projects
		if r.URL.Query().Get("admin") == "1" && account.GlobalAdmin && account.Status == "active" && account.Verified != nil {
			view, err := s.adminService.View(r.Context())
			if err != nil {
				problem(w, 503, "admin unavailable")
				return
			}
			state["admin"] = view
		}
	}
	jsonResponse(w, 200, state)
}
