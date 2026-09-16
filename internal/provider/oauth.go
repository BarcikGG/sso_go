package provider

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/store/postgres"
)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	ar, err := s.oauth.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		problem(w, 400, "invalid authorization request")
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("scope") == "" || !strings.Contains(" "+q.Get("scope")+" ", " openid ") || len(q.Get("state")) < 16 || len(q.Get("nonce")) < 16 || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) < 43 {
		problem(w, 400, "invalid OIDC or PKCE parameters")
		return
	}
	c, err := s.DB.Client(r.Context(), ar.GetClient().GetID())
	if err != nil {
		problem(w, 400, "unknown client")
		return
	}
	// Fosite checks the client and redirect. Require a byte-for-byte registered URI.
	redirect := q.Get("redirect_uri")
	found := false
	for _, v := range c.Redirects {
		if v == redirect {
			found = true
		}
	}
	if !found {
		problem(w, 400, "redirect URI not registered")
		return
	}
	user, err := s.session(r)
	if err != nil {
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	a, err := s.DB.Account(r.Context(), user)
	if err != nil || a.Verified == nil {
		problem(w, 403, "email not verified")
		return
	}
	if _, err = s.DB.Access(r.Context(), user, c.Project); err != nil {
		target, _ := url.Parse(redirect)
		values := target.Query()
		values.Set("error", "access_pending")
		values.Set("state", q.Get("state"))
		target.RawQuery = values.Encode()
		http.Redirect(w, r, target.String(), http.StatusFound)
		return
	}
	code := random()
	scopes := strings.Fields(q.Get("scope"))
	_, err = s.DB.Pool.Exec(r.Context(), "INSERT INTO authorization_codes(code_hash,account_id,client_id,redirect_uri,nonce,code_challenge,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,now()+interval '2 minutes')", postgres.Hash(code), user, c.ID, redirect, q.Get("nonce"), q.Get("code_challenge"), scopes)
	if err != nil {
		problem(w, 500, "authorization failed")
		return
	}
	target, _ := url.Parse(redirect)
	query := target.Query()
	query.Set("code", code)
	query.Set("state", q.Get("state"))
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		problem(w, 400, "invalid form")
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id = r.FormValue("client_id")
		secret = r.FormValue("client_secret")
	}
	c, err := s.DB.Client(r.Context(), id)
	if err != nil || subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(postgres.Hash(secret))) != 1 {
		problem(w, 401, "invalid_client")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, c)
	case "refresh_token":
		s.refresh(w, r, c)
	default:
		problem(w, 400, "unsupported_grant_type")
	}
}
func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, c postgres.Client) {
	ctx := r.Context()
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	defer tx.Rollback(ctx)
	var user, clientID, redirect, nonce, challenge string
	var scopes []string
	err = tx.QueryRow(ctx, "UPDATE authorization_codes SET used_at=now() WHERE code_hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING account_id,client_id,redirect_uri,nonce,code_challenge,scopes", postgres.Hash(r.FormValue("code"))).Scan(&user, &clientID, &redirect, &nonce, &challenge, &scopes)
	if err != nil || clientID != c.ID || redirect != r.FormValue("redirect_uri") {
		problem(w, 400, "invalid_grant")
		return
	}
	verifier := r.FormValue("code_verifier")
	vsum := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(vsum[:])
	if len(verifier) < 43 || subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) != 1 {
		problem(w, 400, "invalid_grant")
		return
	}
	if err = tx.Commit(ctx); err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	s.issue(w, r, user, c, nonce, scopes, "", false)
}
func (s *Server) refresh(w http.ResponseWriter, r *http.Request, c postgres.Client) {
	ctx := r.Context()
	raw := r.FormValue("refresh_token")
	if raw == "" {
		problem(w, 400, "invalid_grant")
		return
	}
	tx, err := s.DB.Pool.Begin(ctx)
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	defer tx.Rollback(ctx)
	var family, user, clientID, project string
	var scopes []string
	var used, revoked *time.Time
	var expires time.Time
	err = tx.QueryRow(ctx, "SELECT family_id,account_id,client_id,project_id,scopes,expires_at,used_at,revoked_at FROM refresh_tokens WHERE token_hash=$1 FOR UPDATE", postgres.Hash(raw)).Scan(&family, &user, &clientID, &project, &scopes, &expires, &used, &revoked)
	if err != nil || clientID != c.ID || project != c.Project {
		problem(w, 400, "invalid_grant")
		return
	}
	if used != nil || revoked != nil {
		_, _ = tx.Exec(ctx, "UPDATE refresh_tokens SET revoked_at=now() WHERE family_id=$1 AND revoked_at IS NULL", family)
		_ = tx.Commit(ctx)
		problem(w, 400, "refresh_reuse_detected")
		return
	}
	if !expires.After(time.Now()) {
		problem(w, 400, "invalid_grant")
		return
	}
	// The row lock serializes rotation. A second request sees used_at and revokes the family.
	if _, err = tx.Exec(ctx, "UPDATE refresh_tokens SET used_at=now() WHERE token_hash=$1", postgres.Hash(raw)); err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	next := random()
	_, err = tx.Exec(ctx, "INSERT INTO refresh_tokens(token_hash,family_id,account_id,client_id,project_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days')", postgres.Hash(next), family, user, c.ID, c.Project, scopes)
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	if err = tx.Commit(ctx); err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	s.issue(w, r, user, c, "", scopes, next, true)
}
func (s *Server) issue(w http.ResponseWriter, r *http.Request, user string, c postgres.Client, nonce string, scopes []string, refresh string, isRefresh bool) {
	ctx := r.Context()
	a, err := s.DB.Account(ctx, user)
	if err != nil || a.Verified == nil {
		problem(w, 400, "invalid_grant")
		return
	}
	roles, err := s.DB.Access(ctx, user, c.Project)
	if err != nil {
		problem(w, 403, "access_revoked")
		return
	}
	if !isRefresh {
		refresh = random()
		_, err = s.DB.Pool.Exec(ctx, "INSERT INTO refresh_tokens(token_hash,family_id,account_id,client_id,project_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '7 days')", postgres.Hash(refresh), random(), user, c.ID, c.Project, scopes)
		if err != nil {
			problem(w, 500, "token unavailable")
			return
		}
	}
	access, err := s.keys.Sign(ctx, map[string]any{"sub": user, "aud": c.Project, "client_id": c.ID, "roles": roles, "scope": strings.Join(scopes, " ")}, "at+jwt")
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	idClaims := map[string]any{"sub": user, "aud": c.ID, "email": a.Email, "email_verified": true, "name": a.Name, "picture": a.Avatar}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	idToken, err := s.keys.Sign(ctx, idClaims, "JWT")
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	management, err := s.keys.Sign(ctx, map[string]any{"sub": user, "aud": s.issuer + "/grpc", "client_id": c.ID, "project_id": c.Project, "roles": roles}, "at+jwt")
	if err != nil {
		problem(w, 500, "token unavailable")
		return
	}
	jsonResponse(w, 200, map[string]any{"access_token": access, "id_token": idToken, "refresh_token": refresh, "management_token": management, "token_type": "Bearer", "expires_in": 300, "scope": strings.Join(scopes, " ")})
}
func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		problem(w, 401, "missing bearer token")
		return
	}
	raw := strings.TrimPrefix(header, "Bearer ")
	if raw == "" {
		problem(w, 401, "missing token")
		return
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		problem(w, 401, "invalid token")
		return
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		problem(w, 401, "invalid token")
		return
	}
	var untrusted map[string]any
	if json.Unmarshal(pb, &untrusted) != nil {
		problem(w, 401, "invalid token")
		return
	}
	aud, _ := untrusted["aud"].(string)
	claims, err := s.keys.Verify(r.Context(), raw, aud, "at+jwt")
	if err != nil {
		problem(w, 401, "invalid token")
		return
	}
	user, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	c, err := s.DB.Client(r.Context(), clientID)
	if err != nil || c.Project != aud {
		problem(w, 401, "invalid audience")
		return
	}
	if _, err = s.DB.Access(r.Context(), user, aud); err != nil {
		problem(w, 403, "access revoked")
		return
	}
	a, err := s.DB.Account(r.Context(), user)
	if err != nil {
		problem(w, 401, "invalid token")
		return
	}
	jsonResponse(w, 200, map[string]any{"sub": a.ID, "email": a.Email, "email_verified": a.Verified != nil, "name": a.Name, "picture": a.Avatar})
}
