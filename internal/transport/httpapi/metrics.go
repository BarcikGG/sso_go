package httpapi

import (
	"fmt"
	"net/http"
)

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	m, err := s.system.Metrics(r.Context())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "sso_outbox_pending %d\nsso_outbox_retried %d\nsso_outbox_oldest_age_seconds %g\n", m.Pending, m.Retried, m.OldestAgeSeconds)
}
