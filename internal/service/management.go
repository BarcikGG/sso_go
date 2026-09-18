package service

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/token"
)

var (
	ErrUnauthenticated = errors.New("invalid service or user credentials")
	ErrForbidden       = errors.New("permission denied")
)

type Management struct {
	Repo   *postgres.DB
	Keys   *token.KeySet
	Issuer string
}
type Actor struct {
	User, Client, Project string
	Roles                 []string
}

func hasRole(roles []string, role string) bool {
	for _, x := range roles {
		if x == role {
			return true
		}
	}
	return false
}

func (s Management) Authenticate(ctx context.Context, project, clientID, secret, bearer string, admin bool) (Actor, error) {
	c, err := s.Repo.Client(ctx, clientID)
	if postgres.IsNotFound(err) {
		return Actor{}, ErrUnauthenticated
	}
	if err != nil {
		return Actor{}, err
	}
	if c.Project != project || subtle.ConstantTimeCompare([]byte(c.SecretHash), []byte(postgres.Hash(secret))) != 1 {
		return Actor{}, ErrUnauthenticated
	}
	claims, err := s.Keys.Verify(ctx, bearer, s.Issuer+"/grpc", "at+jwt")
	if err != nil || claims["client_id"] != clientID || claims["project_id"] != project {
		return Actor{}, ErrUnauthenticated
	}
	user, _ := claims["sub"].(string)
	if user == "" {
		return Actor{}, ErrUnauthenticated
	}
	a, err := s.Repo.Account(ctx, user)
	if postgres.IsNotFound(err) {
		return Actor{}, ErrForbidden
	}
	if err != nil {
		return Actor{}, err
	}
	if a.Status != "active" || a.Verified == nil {
		return Actor{}, ErrForbidden
	}
	roles, err := s.Repo.Access(ctx, user, project)
	if postgres.IsNotFound(err) {
		return Actor{}, ErrForbidden
	}
	if err != nil {
		return Actor{}, err
	}
	if admin && !hasRole(roles, "admin") {
		return Actor{}, ErrForbidden
	}
	return Actor{User: user, Client: c.ID, Project: project, Roles: roles}, nil
}

func (s Management) GetUser(ctx context.Context, actor Actor, id string) (map[string]any, error) {
	if id == "" {
		id = actor.User
	}
	if id != actor.User && !hasRole(actor.Roles, "admin") {
		return nil, ErrForbidden
	}
	a, err := s.Repo.Account(ctx, id)
	if err != nil {
		return nil, storageError(err)
	}
	roles, err := s.Repo.Access(ctx, id, actor.Project)
	if postgres.IsNotFound(err) {
		roles = []string{}
	} else if err != nil {
		return nil, err
	}
	return map[string]any{"user_id": a.ID, "email": a.Email, "name": a.Name, "avatar_url": a.Avatar, "roles": roles}, nil
}

func (s Management) UpdateProfile(ctx context.Context, actor Actor, id, name, avatar string) (map[string]any, error) {
	if id == "" {
		id = actor.User
	}
	if id != actor.User {
		return nil, ErrForbidden
	}
	name, avatar = strings.TrimSpace(name), strings.TrimSpace(avatar)
	if name == "" || len(name) > 200 || len(avatar) > 2048 {
		return nil, ErrInvalidInput
	}
	result, err := s.Repo.UpdateLegacyProfile(ctx, actor.User, actor.Client, actor.Project, id, name, avatar)
	return result, storageError(err)
}

func (s Management) ListRequests(ctx context.Context, actor Actor) ([]postgres.AccessRequest, error) {
	return s.Repo.PendingRequests(ctx, actor.Project)
}

func (s Management) Approve(ctx context.Context, actor Actor, request string, roles []string) (map[string]any, error) {
	if len(roles) == 0 {
		roles = []string{"member"}
	}
	if err := validateRoleSlice(roles); err != nil {
		return nil, ErrInvalidInput
	}
	result, err := s.Repo.ApproveRequest(ctx, actor.User, actor.Client, actor.Project, request, roles)
	return result, storageError(err)
}

func (s Management) SetRoles(ctx context.Context, actor Actor, id string, roles []string) (map[string]any, error) {
	if id == "" || validateRoleSlice(roles) != nil {
		return nil, ErrInvalidInput
	}
	result, err := s.Repo.SetProjectRoles(ctx, actor.User, actor.Client, actor.Project, id, roles)
	return result, storageError(err)
}

func (s Management) Revoke(ctx context.Context, actor Actor, id string) error {
	if id == "" {
		return ErrInvalidInput
	}
	return storageError(s.Repo.RevokeProjectAccess(ctx, actor.User, actor.Client, actor.Project, id))
}

func validateRoleSlice(roles []string) error {
	if len(roles) == 0 || len(roles) > 10 {
		return ErrInvalidInput
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if !rolePattern.MatchString(role) || seen[role] {
			return ErrInvalidInput
		}
		seen[role] = true
	}
	return nil
}
