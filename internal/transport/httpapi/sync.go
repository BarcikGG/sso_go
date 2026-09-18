package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/endl/sso_go/internal/service"
)

func (s *Server) syncProject(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		problem(w, http.StatusUnauthorized, "invalid_client")
		return "", false
	}
	project, err := s.syncService.ClientProject(r.Context(), id, secret)
	if errors.Is(err, service.ErrInvalidClient) {
		problem(w, http.StatusUnauthorized, "invalid_client")
		return "", false
	}
	if err != nil {
		problem(w, 500, "sync unavailable")
		return "", false
	}
	return project, true
}

func (s *Server) syncSnapshot(w http.ResponseWriter, r *http.Request) {
	project, ok := s.syncProject(w, r)
	if !ok {
		return
	}
	after := r.URL.Query().Get("after_user")
	if len(after) > 128 {
		problem(w, 400, "invalid cursor")
		return
	}
	var cursor *int64
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			problem(w, 400, "invalid cursor")
			return
		}
		cursor = &value
	}
	result, err := s.syncService.Snapshot(r.Context(), project, after, cursor)
	if err != nil {
		problem(w, 500, "snapshot unavailable")
		return
	}
	jsonResponse(w, 200, result)
}

func (s *Server) syncChanges(w http.ResponseWriter, r *http.Request) {
	project, ok := s.syncProject(w, r)
	if !ok {
		return
	}
	cursor, err := strconv.ParseInt(strings.TrimSpace(r.URL.Query().Get("after")), 10, 64)
	if err != nil || cursor < 0 {
		problem(w, 400, "invalid cursor")
		return
	}
	events, next, err := s.syncService.Changes(r.Context(), project, cursor)
	if err != nil {
		problem(w, 500, "changes unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"project_id": project, "next_cursor": next, "events": events})
}
