package service

import (
	"context"
	"errors"
	"log"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/endl/sso_go/internal/repository/postgres"
	"github.com/endl/sso_go/internal/security"
)

var (
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnverified         = errors.New("email unverified")
	ErrDisabled           = errors.New("account disabled")
)
var loginPattern = regexp.MustCompile(`^[a-z0-9._-]{3,32}$`)

type Mailer interface {
	Send(to, subject, link string) error
}
type Identity struct {
	Repo      *postgres.DB
	Passwords *security.PasswordHasher
	Mailer    Mailer
	Issuer    string
}

type Registration struct{ Email, Login, GivenName, FamilyName, Name, Password string }
type UserProject = postgres.UserProject

func (s Identity) Register(ctx context.Context, in Registration) error {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	login := strings.ToLower(strings.TrimSpace(in.Login))
	if login == "" {
		login = email
	} // Backward compatible with the existing pilot form.
	given, family := strings.TrimSpace(in.GivenName), strings.TrimSpace(in.FamilyName)
	name := strings.TrimSpace(given + " " + family)
	if name == "" {
		name = strings.TrimSpace(in.Name)
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || parsed.Address != email || len(email) > 254 || len(login) > 254 || login != email && !loginPattern.MatchString(login) || len(given) > 100 || len(family) > 100 || len(name) > 200 || len(in.Password) < 12 || len(in.Password) > 1024 {
		return ErrInvalidInput
	}
	hash, err := s.Passwords.Hash(in.Password)
	if err != nil {
		return err
	}
	id, err := security.NewUUIDv7()
	if err != nil {
		return err
	}
	token := security.RandomToken()
	err = s.Repo.CreatePendingAccount(ctx, postgres.PendingAccount{ID: id, Email: email, Login: login, PasswordHash: hash, Name: name, GivenName: given, FamilyName: family, VerificationHash: postgres.Hash(token)})
	if err != nil {
		return storageError(err)
	}
	return s.Mailer.Send(email, "Confirm your email", s.Issuer+"/verify?token="+url.QueryEscape(token))
}

func (s Identity) ResendVerification(ctx context.Context, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	id, err := s.Repo.UnverifiedAccountID(ctx, email)
	if err != nil {
		return nil
	}
	token := security.RandomToken()
	if err = s.Repo.AddEmailVerification(ctx, id, postgres.Hash(token)); err != nil {
		return err
	}
	return s.Mailer.Send(email, "Confirm your email", s.Issuer+"/verify?token="+url.QueryEscape(token))
}

func (s Identity) VerifyEmail(ctx context.Context, token string) error {
	if token == "" {
		return ErrInvalidInput
	}
	return storageError(s.Repo.VerifyEmail(ctx, postgres.Hash(token)))
}

func (s Identity) Login(ctx context.Context, identifier, password, token string) (string, error) {
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	var status string
	var legacyID, legacyHash string
	err := s.Repo.WithLogin(ctx, identifier, func(a postgres.LoginAccount, create func(string) error) error {
		ok, err := s.Passwords.Verify(password, a.PasswordHash)
		if err != nil || !ok {
			return ErrInvalidCredentials
		}
		if a.Verified == nil {
			return ErrUnverified
		}
		if a.Status == "disabled" {
			return ErrDisabled
		}
		status = a.Status
		if security.IsLegacyBcrypt(a.PasswordHash) {
			legacyID, legacyHash = a.ID, a.PasswordHash
		}
		return create(postgres.Hash(token))
	})
	if postgres.IsNotFound(err) {
		return "", ErrInvalidCredentials
	}
	if err == nil && legacyID != "" {
		upgraded, hashErr := s.Passwords.Hash(password)
		if hashErr == nil {
			hashErr = s.Repo.UpgradePasswordHash(ctx, legacyID, legacyHash, upgraded)
		}
		if hashErr != nil {
			log.Printf("legacy password upgrade failed for account %s: %v", legacyID, hashErr)
		}
	}
	return status, err
}

func (s Identity) Session(ctx context.Context, token string) (string, error) {
	return s.Repo.SessionAccount(ctx, postgres.Hash(token))
}
func (s Identity) Logout(ctx context.Context, token string) error {
	return s.Repo.DeleteSession(ctx, postgres.Hash(token))
}
func (s Identity) Account(ctx context.Context, id string) (postgres.Account, error) {
	return s.Repo.Account(ctx, id)
}
func (s Identity) Projects(ctx context.Context, id string) ([]postgres.UserProject, error) {
	return s.Repo.UserProjects(ctx, id)
}

func (s Identity) RequestAccess(ctx context.Context, id, project string) error {
	a, err := s.Repo.Account(ctx, id)
	if err != nil {
		return err
	}
	if a.Verified == nil {
		return ErrUnverified
	}
	if _, err = s.Repo.Access(ctx, id, project); err == nil {
		return nil
	}
	if !postgres.IsNotFound(err) {
		return err
	}
	return s.Repo.RequestAccess(ctx, security.RandomToken(), id, project)
}

func (s Identity) ForgotPassword(ctx context.Context, email string) {
	email = strings.ToLower(strings.TrimSpace(email))
	id, err := s.Repo.PasswordResetAccount(ctx, email)
	if err != nil {
		return
	}
	token := security.RandomToken()
	if err = s.Repo.AddPasswordReset(ctx, id, postgres.Hash(token)); err == nil {
		err = s.Mailer.Send(email, "Reset your SSO password", s.Issuer+"/password/reset?token="+url.QueryEscape(token))
	}
	if err != nil {
		log.Printf("password reset delivery: %v", err)
	}
}

func (s Identity) ResetPassword(ctx context.Context, token, password string) error {
	if len(password) < 12 || len(password) > 1024 || len(token) < 32 {
		return ErrInvalidInput
	}
	hash, err := s.Passwords.Hash(password)
	if err != nil {
		return err
	}
	err = storageError(s.Repo.ResetPassword(ctx, postgres.Hash(token), hash))
	if errors.Is(err, ErrNotFound) {
		return ErrInvalidInput
	}
	return err
}

func (s Identity) ChangePassword(ctx context.Context, id, current, next string) error {
	if len(next) < 12 || len(next) > 1024 {
		return ErrInvalidInput
	}
	hash, err := s.Passwords.Hash(next)
	if err != nil {
		return err
	}
	err = s.Repo.ChangePassword(ctx, id, hash, func(stored string) (bool, error) { return s.Passwords.Verify(current, stored) })
	if errors.Is(err, postgres.ErrInvalidPassword) {
		return ErrInvalidCredentials
	}
	return storageError(err)
}

func (s Identity) UpdateProfile(ctx context.Context, id, login, given, family, avatar string) error {
	login = strings.ToLower(strings.TrimSpace(login))
	given, family, avatar = strings.TrimSpace(given), strings.TrimSpace(family), strings.TrimSpace(avatar)
	if !loginPattern.MatchString(login) || len(given) > 100 || len(family) > 100 || len(avatar) > 2048 {
		return ErrInvalidInput
	}
	return storageError(s.Repo.UpdateProfile(ctx, id, postgres.ProfileUpdate{Login: login, GivenName: given, FamilyName: family, Name: strings.TrimSpace(given + " " + family), Avatar: avatar}))
}
