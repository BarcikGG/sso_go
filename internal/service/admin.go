package service

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/endl/sso_go/internal/repository/postgres"
)

var rolePattern = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,63}$`)

type Admin struct{ Repo *postgres.DB }
type AdminView = postgres.AdminView

func (s Admin) Authorized(ctx context.Context, actor string) bool {
	a, err := s.Repo.Account(ctx, actor)
	return err == nil && a.Status == "active" && a.Verified != nil && a.GlobalAdmin
}

func (s Admin) View(ctx context.Context) (postgres.AdminView, error) { return s.Repo.AdminView(ctx) }
func (s Admin) Activate(ctx context.Context, actor, id string) error {
	return storageError(s.Repo.ActivateAccount(ctx, actor, id))
}
func (s Admin) Disable(ctx context.Context, actor, id string) error {
	if actor == id {
		return errors.New("cannot disable own account")
	}
	return storageError(s.Repo.DisableAccount(ctx, actor, id))
}

func ParseRoles(raw string) ([]string, error) {
	seen := map[string]bool{}
	roles := []string{}
	for _, part := range strings.Split(raw, ",") {
		role := strings.TrimSpace(part)
		if !rolePattern.MatchString(role) || seen[role] {
			return nil, errors.New("invalid or duplicate role")
		}
		seen[role] = true
		roles = append(roles, role)
		if len(roles) > 10 {
			return nil, errors.New("too many roles")
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("roles required")
	}
	return roles, nil
}

func (s Admin) Grant(ctx context.Context, actor, user, project, rawRoles string) error {
	if user == "" || project == "" {
		return errors.New("user and project required")
	}
	roles, err := ParseRoles(rawRoles)
	if err != nil {
		return err
	}
	return storageError(s.Repo.GrantAccess(ctx, actor, user, project, roles))
}

func (s Admin) Revoke(ctx context.Context, actor, user, project string) error {
	if user == "" || project == "" {
		return errors.New("user and project required")
	}
	return storageError(s.Repo.RevokeAccess(ctx, actor, user, project))
}
