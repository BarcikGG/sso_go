package service

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/security"
	"github.com/endl/sso_go/internal/token"
)

var (
	ErrPending       = errors.New("project access pending")
	ErrInvalidClient = errors.New("invalid client")
	ErrInvalidGrant  = errors.New("invalid grant")
	ErrAccessRevoked = errors.New("project access revoked")
)
var pkceChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

type OAuth struct {
	Repo   *postgres.DB
	Keys   *token.KeySet
	Issuer string
}
type AuthorizeInput struct{ ClientID, Redirect, ResponseType, Scope, State, Nonce, Challenge, ChallengeMethod, User string }

func (s OAuth) Authorize(ctx context.Context, in AuthorizeInput) (string, error) {
	if in.ResponseType != "code" || !strings.Contains(" "+in.Scope+" ", " openid ") || len(in.State) < 16 || len(in.State) > 512 || len(in.Nonce) < 16 || len(in.Nonce) > 256 || in.ChallengeMethod != "S256" || !pkceChallengePattern.MatchString(in.Challenge) {
		return "", ErrInvalidInput
	}
	for _, scope := range strings.Fields(in.Scope) {
		switch scope {
		case "openid", "profile", "email", "offline_access":
		default:
			return "", ErrInvalidInput
		}
	}
	client, err := s.Repo.Client(ctx, in.ClientID)
	if postgres.IsNotFound(err) {
		return "", ErrInvalidClient
	}
	if err != nil {
		return "", err
	}
	found := false
	for _, uri := range client.Redirects {
		if uri == in.Redirect {
			found = true
			break
		}
	}
	if !found {
		return "", ErrInvalidInput
	}
	if in.User == "" {
		return "", ErrUnauthenticated
	}
	a, err := s.Repo.Account(ctx, in.User)
	if postgres.IsNotFound(err) {
		return "", ErrForbidden
	}
	if err != nil {
		return "", err
	}
	if a.Verified == nil {
		return "", ErrForbidden
	}
	if a.Status != "active" {
		return "", ErrPending
	}
	if _, err = s.Repo.Access(ctx, in.User, client.Project); postgres.IsNotFound(err) {
		return "", ErrPending
	}
	if err != nil {
		return "", err
	}
	code := security.RandomToken()
	err = s.Repo.CreateAuthorizationCode(ctx, postgres.Hash(code), postgres.AuthorizationCode{Account: in.User, Client: client.ID, Redirect: in.Redirect, Nonce: in.Nonce, Challenge: in.Challenge, Scopes: strings.Fields(in.Scope)})
	return code, err
}

func (s OAuth) Client(ctx context.Context, id, secret string) (postgres.Client, error) {
	c, err := s.Repo.Client(ctx, id)
	if postgres.IsNotFound(err) {
		return c, ErrInvalidClient
	}
	if err != nil {
		return c, err
	}
	if subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(postgres.Hash(secret))) != 1 {
		return c, ErrInvalidClient
	}
	return c, nil
}

func (s OAuth) JWKS(ctx context.Context) (any, error) { return s.Keys.JWKS(ctx) }

func (s OAuth) Exchange(ctx context.Context, c postgres.Client, code, redirect, verifier string) (map[string]any, error) {
	if !pkceVerifierPattern.MatchString(verifier) {
		return nil, ErrInvalidGrant
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	grant, err := s.Repo.ConsumeAuthorizationCode(ctx, postgres.Hash(code), c.ID, redirect, func(expected string) bool {
		return subtle.ConstantTimeCompare([]byte(challenge), []byte(expected)) == 1
	})
	if postgres.IsNotFound(err) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	return s.issue(ctx, grant.Account, c, grant.Nonce, grant.Scopes, "", false)
}

func (s OAuth) Refresh(ctx context.Context, c postgres.Client, raw string) (map[string]any, error) {
	if raw == "" {
		return nil, ErrInvalidGrant
	}
	next := security.RandomToken()
	grant, err := s.Repo.RotateRefresh(ctx, postgres.Hash(raw), postgres.Hash(next), c.ID, c.Project, time.Now())
	if err != nil {
		if errors.Is(err, postgres.ErrRefreshReuse) {
			return nil, ErrRefreshReuse
		}
		if postgres.IsNotFound(err) {
			return nil, ErrInvalidGrant
		}
		return nil, err
	}
	return s.issue(ctx, grant.Account, c, "", grant.Scopes, next, true)
}

func (s OAuth) issue(ctx context.Context, user string, c postgres.Client, nonce string, scopes []string, refresh string, isRefresh bool) (map[string]any, error) {
	a, err := s.Repo.Account(ctx, user)
	if postgres.IsNotFound(err) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if a.Verified == nil || a.Status != "active" {
		return nil, ErrInvalidGrant
	}
	roles, err := s.Repo.Access(ctx, user, c.Project)
	if postgres.IsNotFound(err) {
		return nil, ErrAccessRevoked
	}
	if err != nil {
		return nil, err
	}
	if !isRefresh {
		refresh = security.RandomToken()
		if err = s.Repo.CreateRefresh(ctx, postgres.Hash(refresh), security.RandomToken(), user, c.ID, c.Project, scopes); err != nil {
			return nil, err
		}
	}
	access, err := s.Keys.Sign(ctx, map[string]any{"sub": user, "aud": c.Project, "client_id": c.ID, "roles": roles, "scope": strings.Join(scopes, " ")}, "at+jwt")
	if err != nil {
		return nil, err
	}
	idClaims := map[string]any{"sub": user, "aud": c.ID, "email": a.Email, "email_verified": true, "preferred_username": a.Login, "name": a.Name, "given_name": a.GivenName, "family_name": a.FamilyName, "picture": a.Avatar}
	if nonce != "" {
		idClaims["nonce"] = nonce
	}
	idToken, err := s.Keys.Sign(ctx, idClaims, "JWT")
	if err != nil {
		return nil, err
	}
	management, err := s.Keys.Sign(ctx, map[string]any{"sub": user, "aud": s.Issuer + "/grpc", "client_id": c.ID, "project_id": c.Project, "roles": roles}, "at+jwt")
	if err != nil {
		return nil, err
	}
	return map[string]any{"access_token": access, "id_token": idToken, "refresh_token": refresh, "management_token": management, "token_type": "Bearer", "expires_in": 300, "scope": strings.Join(scopes, " ")}, nil
}

func (s OAuth) Userinfo(ctx context.Context, raw string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidGrant
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidGrant
	}
	var untrusted map[string]any
	if json.Unmarshal(payload, &untrusted) != nil {
		return nil, ErrInvalidGrant
	}
	audience, _ := untrusted["aud"].(string)
	claims, err := s.Keys.Verify(ctx, raw, audience, "at+jwt")
	if err != nil {
		return nil, ErrInvalidGrant
	}
	user, _ := claims["sub"].(string)
	clientID, _ := claims["client_id"].(string)
	client, err := s.Repo.Client(ctx, clientID)
	if postgres.IsNotFound(err) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if client.Project != audience {
		return nil, ErrInvalidGrant
	}
	if _, err = s.Repo.Access(ctx, user, audience); postgres.IsNotFound(err) {
		return nil, ErrAccessRevoked
	}
	if err != nil {
		return nil, err
	}
	a, err := s.Repo.Account(ctx, user)
	if postgres.IsNotFound(err) {
		return nil, ErrInvalidGrant
	}
	if err != nil {
		return nil, err
	}
	if a.Status != "active" {
		return nil, ErrInvalidGrant
	}
	return map[string]any{"sub": a.ID, "email": a.Email, "email_verified": a.Verified != nil, "preferred_username": a.Login, "name": a.Name, "given_name": a.GivenName, "family_name": a.FamilyName, "picture": a.Avatar}, nil
}
