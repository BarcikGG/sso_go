package provider

import (
	"fmt"
	"net/http"
)

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	var pending, failed int64
	var age float64
	err := s.DB.Pool.QueryRow(r.Context(), "SELECT count(*),count(*) FILTER (WHERE attempts>0),coalesce(extract(epoch from now()-min(created_at)),0) FROM outbox WHERE published_at IS NULL").Scan(&pending, &failed, &age)
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "sso_outbox_pending %d\nsso_outbox_retried %d\nsso_outbox_oldest_age_seconds %g\n", pending, failed, age)
}
