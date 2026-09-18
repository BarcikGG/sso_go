package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/service"
)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	ar, err := s.oauth.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		problem(w, 400, "invalid authorization request")
		return
	}
	q := r.URL.Query()
	user, _ := s.session(r)
	input := service.AuthorizeInput{ClientID: ar.GetClient().GetID(), Redirect: q.Get("redirect_uri"), ResponseType: q.Get("response_type"), Scope: q.Get("scope"), State: q.Get("state"), Nonce: q.Get("nonce"), Challenge: q.Get("code_challenge"), ChallengeMethod: q.Get("code_challenge_method"), User: user}
	code, err := s.oidc.Authorize(r.Context(), input)
	switch {
	case errors.Is(err, service.ErrUnauthenticated):
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	case errors.Is(err, service.ErrPending):
		redirectPending(w, r, input.Redirect, input.State)
		return
	case errors.Is(err, service.ErrForbidden):
		problem(w, 403, "email not verified")
		return
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrInvalidClient):
		problem(w, 400, "invalid OIDC or PKCE parameters")
		return
	case err != nil:
		problem(w, 500, "authorization failed")
		return
	}
	target, _ := url.Parse(input.Redirect)
	query := target.Query()
	query.Set("code", code)
	query.Set("state", input.State)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectPending(w http.ResponseWriter, r *http.Request, redirect, state string) {
	target, _ := url.Parse(redirect)
	values := target.Query()
	values.Set("error", "access_pending")
	values.Set("state", state)
	target.RawQuery = values.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "invalid form")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.FormValue("client_id"), r.FormValue("client_secret")
	}
	if !s.allowAttempt(r, "token-ip", s.clientIP(r), 300, 15*time.Minute) || !s.allowAttempt(r, "token-client", id, 300, 15*time.Minute) {
		problem(w, 429, "too many attempts")
		return
	}
	client, err := s.oidc.Client(r.Context(), id, secret)
	if errors.Is(err, service.ErrInvalidClient) {
		problem(w, 401, "invalid_client")
		return
	}
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	var result map[string]any
	switch r.FormValue("grant_type") {
	case "authorization_code":
		result, err = s.oidc.Exchange(r.Context(), client, r.FormValue("code"), r.FormValue("redirect_uri"), r.FormValue("code_verifier"))
	case "refresh_token":
		result, err = s.oidc.Refresh(r.Context(), client, r.FormValue("refresh_token"))
	default:
		problem(w, 400, "unsupported_grant_type")
		return
	}
	switch {
	case errors.Is(err, service.ErrRefreshReuse):
		problem(w, 400, "refresh_reuse_detected")
	case errors.Is(err, service.ErrInvalidGrant):
		problem(w, 400, "invalid_grant")
	case errors.Is(err, service.ErrAccessRevoked):
		problem(w, 403, "access_revoked")
	case err != nil:
		problem(w, 500, "token unavailable")
	default:
		jsonResponse(w, 200, result)
	}
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		problem(w, 401, "missing bearer token")
		return
	}
	result, err := s.oidc.Userinfo(r.Context(), strings.TrimPrefix(header, "Bearer "))
	if errors.Is(err, service.ErrAccessRevoked) {
		problem(w, 403, "access revoked")
		return
	}
	if errors.Is(err, service.ErrInvalidGrant) {
		problem(w, 401, "invalid token")
		return
	}
	if err != nil {
		problem(w, 500, "userinfo unavailable")
		return
	}
	jsonResponse(w, 200, result)
}
