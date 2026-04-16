package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/endl/sso_go/internal/config"
	"github.com/endl/sso_go/internal/security"
	tokenutil "github.com/endl/sso_go/internal/token"
)

type Service struct {
	cfg        config.Config
	users      UserStore
	sessions   SessionStore
	passwords  *security.PasswordHasher
	accessAuth *tokenutil.AccessSigner
}

func NewService(cfg config.Config, users UserStore, sessions SessionStore) (*Service, error) {
	accessAuth, err := tokenutil.NewAccessSigner(cfg.Token.Issuer, cfg.Token.SigningKey)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:        cfg,
		users:      users,
		sessions:   sessions,
		passwords:  security.NewPasswordHasher(),
		accessAuth: accessAuth,
	}, nil
}

func (s *Service) BootstrapAdmin(ctx context.Context) error {
	if s.cfg.Bootstrap.AdminPassword == "" {
		return nil
	}

	hash, err := s.passwords.Hash(s.cfg.Bootstrap.AdminPassword)
	if err != nil {
		return fmt.Errorf("hash bootstrap admin password: %w", err)
	}

	user := User{
		ID:           tokenutil.NewID(),
		Email:        strings.ToLower(strings.TrimSpace(s.cfg.Bootstrap.AdminEmail)),
		Username:     strings.TrimSpace(s.cfg.Bootstrap.AdminUsername),
		PasswordHash: hash,
		IsActive:     true,
		Roles:        []string{"admin"},
		Permissions:  []string{"auth:login", "auth:logout", "users:manage", "sessions:manage"},
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	if user.Email == "" {
		user.Email = "admin@example.local"
	}
	if user.Username == "" {
		user.Username = "admin"
	}

	if err := s.users.SaveUser(ctx, user); err != nil {
		return fmt.Errorf("save bootstrap admin: %w", err)
	}

	return nil
}

func (s *Service) Login(ctx context.Context, input LoginInput) (TokenPair, error) {
	user, err := s.users.FindUserByLogin(ctx, input.Login)
	if err != nil {
		return TokenPair{}, ErrInvalidCredentials
	}

	ok, err := s.passwords.Verify(input.Password, user.PasswordHash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok || !user.IsActive {
		return TokenPair{}, ErrInvalidCredentials
	}

	plainRefresh, hashedRefresh, err := tokenutil.NewRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}

	now := time.Now().UTC()
	session := Session{
		ID:               tokenutil.NewID(),
		UserID:           user.ID,
		RefreshTokenHash: hashedRefresh,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.cfg.Token.RefreshTokenTTL),
	}

	if err := s.sessions.SaveSession(ctx, session); err != nil {
		return TokenPair{}, fmt.Errorf("save session: %w", err)
	}

	accessToken, expiresAt, err := s.accessAuth.Sign(tokenutil.AccessClaims{
		Subject:     user.ID,
		Audience:    effectiveAudience(input.Audience),
		SessionID:   session.ID,
		Roles:       user.Roles,
		Permissions: user.Permissions,
		ExpiresIn:   s.cfg.Token.AccessTokenTTL,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: plainRefresh,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) Refresh(ctx context.Context, refreshToken string) (TokenPair, error) {
	session, err := s.sessions.FindSessionByRefreshTokenHash(ctx, tokenutil.HashRefreshToken(refreshToken))
	if err != nil {
		return TokenPair{}, ErrInvalidToken
	}
	if session.RevokedAt != nil || time.Now().UTC().After(session.ExpiresAt) {
		return TokenPair{}, ErrInvalidToken
	}

	user, err := s.users.FindUserByID(ctx, session.UserID)
	if err != nil || !user.IsActive {
		return TokenPair{}, ErrUnauthorized
	}

	if err := s.sessions.RevokeSession(ctx, session.ID); err != nil {
		return TokenPair{}, fmt.Errorf("revoke session: %w", err)
	}

	plainRefresh, hashedRefresh, err := tokenutil.NewRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}

	now := time.Now().UTC()
	newSession := Session{
		ID:               tokenutil.NewID(),
		UserID:           user.ID,
		RefreshTokenHash: hashedRefresh,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.cfg.Token.RefreshTokenTTL),
	}

	if err := s.sessions.SaveSession(ctx, newSession); err != nil {
		return TokenPair{}, fmt.Errorf("save refreshed session: %w", err)
	}

	accessToken, expiresAt, err := s.accessAuth.Sign(tokenutil.AccessClaims{
		Subject:     user.ID,
		Audience:    []string{"default"},
		SessionID:   newSession.ID,
		Roles:       user.Roles,
		Permissions: user.Permissions,
		ExpiresIn:   s.cfg.Token.AccessTokenTTL,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: plainRefresh,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) Logout(ctx context.Context, accessToken string) error {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return ErrUnauthorized
	}

	if err := s.sessions.RevokeSession(ctx, claims.SessionID); err != nil {
		return err
	}

	return nil
}

func (s *Service) LogoutAll(ctx context.Context, accessToken string) error {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return ErrUnauthorized
	}

	if err := s.sessions.RevokeAllSessionsByUserID(ctx, claims.Subject); err != nil {
		return err
	}

	return nil
}

func (s *Service) Me(ctx context.Context, accessToken string) (AuthenticatedUser, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return AuthenticatedUser{}, ErrUnauthorized
	}

	session, err := s.sessions.FindSessionByID(ctx, claims.SessionID)
	if err != nil || session.RevokedAt != nil || time.Now().UTC().After(session.ExpiresAt) {
		return AuthenticatedUser{}, ErrUnauthorized
	}

	user, err := s.users.FindUserByID(ctx, claims.Subject)
	if err != nil || !user.IsActive {
		return AuthenticatedUser{}, ErrUnauthorized
	}

	return AuthenticatedUser{
		ID:          user.ID,
		Email:       user.Email,
		Username:    user.Username,
		Roles:       append([]string(nil), user.Roles...),
		Permissions: append([]string(nil), user.Permissions...),
	}, nil
}

func (s *Service) JWKSPayload() (json.RawMessage, error) {
	return s.accessAuth.JWKSPayload()
}

func effectiveAudience(audience string) []string {
	if strings.TrimSpace(audience) == "" {
		return []string{"default"}
	}

	return []string{strings.TrimSpace(audience)}
}

func ExtractBearerToken(header string) (string, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return "", ErrUnauthorized
	}

	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if token == "" {
		return "", ErrUnauthorized
	}

	return token, nil
}

func DebugTokenPayload(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}

	return payload, nil
}
