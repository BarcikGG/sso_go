package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
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
	clients    ClientStore
	audit      AuditStore
	passwords  *security.PasswordHasher
	accessAuth *tokenutil.AccessSigner
}

func NewService(cfg config.Config, users UserStore, sessions SessionStore, clients ClientStore, audit AuditStore) (*Service, error) {
	accessAuth, err := tokenutil.NewAccessSigner(cfg.Token.Issuer, cfg.Token.SigningKey)
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:        cfg,
		users:      users,
		sessions:   sessions,
		clients:    clients,
		audit:      audit,
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

	s.recordAuditEvent(ctx, user.ID, "bootstrap_admin_created", map[string]any{
		"email":    user.Email,
		"username": user.Username,
	})

	return nil
}

func (s *Service) Login(ctx context.Context, input LoginInput) (TokenPair, error) {
	audience, err := s.resolveAudience(ctx, input.Audience)
	if err != nil {
		s.recordAuditEvent(ctx, "", "login_failed", map[string]any{
			"login":    input.Login,
			"audience": input.Audience,
			"cause":    "invalid_audience",
		})
		return TokenPair{}, err
	}

	user, err := s.users.FindUserByLogin(ctx, input.Login)
	if err != nil {
		s.recordAuditEvent(ctx, "", "login_failed", map[string]any{
			"login": input.Login,
			"cause": "user_not_found",
		})
		return TokenPair{}, ErrInvalidCredentials
	}

	ok, err := s.passwords.Verify(input.Password, user.PasswordHash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok || !user.IsActive {
		s.recordAuditEvent(ctx, user.ID, "login_failed", map[string]any{
			"login": input.Login,
			"cause": "invalid_password_or_inactive_user",
		})
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
		FamilyID:         tokenutil.NewID(),
		RefreshTokenHash: hashedRefresh,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.cfg.Token.RefreshTokenTTL),
	}

	if err := s.sessions.SaveSession(ctx, session); err != nil {
		return TokenPair{}, fmt.Errorf("save session: %w", err)
	}

	accessToken, expiresAt, err := s.accessAuth.Sign(tokenutil.AccessClaims{
		SubjectType: "user",
		Subject:     user.ID,
		Audience:    []string{audience},
		SessionID:   session.ID,
		Scopes:      buildScopes(user.Permissions),
		Roles:       user.Roles,
		Permissions: user.Permissions,
		ExpiresIn:   s.cfg.Token.AccessTokenTTL,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}

	s.recordAuditEvent(ctx, user.ID, "login_succeeded", map[string]any{
		"session_id": session.ID,
		"audience":   []string{audience},
	})

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
		s.recordAuditEvent(ctx, "", "refresh_failed", map[string]any{
			"cause": "session_not_found",
		})
		return TokenPair{}, ErrInvalidToken
	}
	if session.RevokedAt != nil || time.Now().UTC().After(session.ExpiresAt) {
		s.recordAuditEvent(ctx, session.UserID, "refresh_failed", map[string]any{
			"session_id": session.ID,
			"cause":      "revoked_or_expired",
		})
		return TokenPair{}, ErrInvalidToken
	}
	if session.UsedAt != nil {
		_ = s.sessions.RevokeSessionFamily(ctx, session.FamilyID)
		s.recordAuditEvent(ctx, session.UserID, "refresh_reuse_detected", map[string]any{
			"session_id": session.ID,
			"family_id":  session.FamilyID,
		})
		return TokenPair{}, ErrInvalidToken
	}

	user, err := s.users.FindUserByID(ctx, session.UserID)
	if err != nil || !user.IsActive {
		s.recordAuditEvent(ctx, session.UserID, "refresh_failed", map[string]any{
			"session_id": session.ID,
			"cause":      "user_not_found_or_inactive",
		})
		return TokenPair{}, ErrUnauthorized
	}

	plainRefresh, hashedRefresh, err := tokenutil.NewRefreshToken()
	if err != nil {
		return TokenPair{}, err
	}

	now := time.Now().UTC()
	newSession := Session{
		ID:               tokenutil.NewID(),
		UserID:           user.ID,
		FamilyID:         session.FamilyID,
		ParentSessionID:  session.ID,
		RefreshTokenHash: hashedRefresh,
		CreatedAt:        now,
		ExpiresAt:        now.Add(s.cfg.Token.RefreshTokenTTL),
	}
	if err := s.sessions.MarkSessionUsed(ctx, session.ID, now, newSession.ID); err != nil {
		return TokenPair{}, fmt.Errorf("mark session used: %w", err)
	}

	if err := s.sessions.SaveSession(ctx, newSession); err != nil {
		return TokenPair{}, fmt.Errorf("save refreshed session: %w", err)
	}

	accessToken, expiresAt, err := s.accessAuth.Sign(tokenutil.AccessClaims{
		SubjectType: "user",
		Subject:     user.ID,
		Audience:    []string{"default"},
		SessionID:   newSession.ID,
		Scopes:      buildScopes(user.Permissions),
		Roles:       user.Roles,
		Permissions: user.Permissions,
		ExpiresIn:   s.cfg.Token.AccessTokenTTL,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign access token: %w", err)
	}

	s.recordAuditEvent(ctx, user.ID, "refresh_succeeded", map[string]any{
		"old_session_id": session.ID,
		"new_session_id": newSession.ID,
	})

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: plainRefresh,
		TokenType:    "Bearer",
		ExpiresAt:    expiresAt,
	}, nil
}

func (s *Service) ClientToken(ctx context.Context, input ClientTokenInput) (TokenPair, error) {
	if s.clients == nil {
		return TokenPair{}, ErrInvalidInput
	}

	client, err := s.clients.FindClientByID(ctx, strings.TrimSpace(input.ClientID))
	if err != nil {
		s.recordAuditEvent(ctx, "", "client_token_failed", map[string]any{
			"client_id": input.ClientID,
			"cause":     "client_not_found",
		})
		return TokenPair{}, ErrInvalidCredentials
	}
	if !client.IsActive {
		s.recordAuditEvent(ctx, client.ID, "client_token_failed", map[string]any{
			"client_id": client.ID,
			"cause":     "client_inactive",
		})
		return TokenPair{}, ErrInvalidCredentials
	}

	ok, err := s.passwords.Verify(input.ClientSecret, client.SecretHash)
	if err != nil {
		return TokenPair{}, fmt.Errorf("verify client secret: %w", err)
	}
	if !ok {
		s.recordAuditEvent(ctx, client.ID, "client_token_failed", map[string]any{
			"client_id": client.ID,
			"cause":     "invalid_secret",
		})
		return TokenPair{}, ErrInvalidCredentials
	}

	audience := strings.TrimSpace(input.Audience)
	if audience == "" {
		audience = client.Audience
	}
	if audience != client.Audience {
		s.recordAuditEvent(ctx, client.ID, "client_token_failed", map[string]any{
			"client_id": client.ID,
			"audience":  audience,
			"cause":     "audience_mismatch",
		})
		return TokenPair{}, ErrInvalidInput
	}

	accessToken, expiresAt, err := s.accessAuth.Sign(tokenutil.AccessClaims{
		SubjectType: "client",
		Subject:     client.ID,
		ClientID:    client.ID,
		Audience:    []string{client.Audience},
		SessionID:   "",
		Scopes:      cloneOrEmpty(client.Scopes),
		Roles:       client.Roles,
		Permissions: client.Permissions,
		ExpiresIn:   s.cfg.Token.AccessTokenTTL,
	})
	if err != nil {
		return TokenPair{}, fmt.Errorf("sign client access token: %w", err)
	}

	s.recordAuditEvent(ctx, client.ID, "client_token_succeeded", map[string]any{
		"client_id": client.ID,
		"audience":  client.Audience,
	})

	return TokenPair{
		AccessToken:  accessToken,
		RefreshToken: "",
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

	s.recordAuditEvent(ctx, claims.Subject, "logout_succeeded", map[string]any{
		"session_id": claims.SessionID,
	})

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

	s.recordAuditEvent(ctx, claims.Subject, "logout_all_succeeded", map[string]any{})

	return nil
}

func (s *Service) Me(ctx context.Context, accessToken string) (AuthenticatedUser, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return AuthenticatedUser{}, ErrUnauthorized
	}

	if claims.SubjectType == "client" {
		if s.clients == nil {
			return AuthenticatedUser{}, ErrUnauthorized
		}
		client, err := s.clients.FindClientByID(ctx, claims.ClientID)
		if err != nil || !client.IsActive {
			return AuthenticatedUser{}, ErrUnauthorized
		}

		return AuthenticatedUser{
			ID:          client.ID,
			SubjectType: "client",
			Email:       "",
			Username:    client.Name,
			IsActive:    client.IsActive,
			Roles:       append([]string(nil), client.Roles...),
			Permissions: append([]string(nil), client.Permissions...),
			Scopes:      append([]string(nil), claims.Scopes...),
			Audience:    append([]string(nil), claims.Audience...),
		}, nil
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
		SubjectType: "user",
		Email:       user.Email,
		Username:    user.Username,
		IsActive:    user.IsActive,
		Roles:       append([]string(nil), user.Roles...),
		Permissions: append([]string(nil), user.Permissions...),
		Scopes:      append([]string(nil), claims.Scopes...),
		Audience:    append([]string(nil), claims.Audience...),
	}, nil
}

func (s *Service) JWKSPayload() (json.RawMessage, error) {
	return s.accessAuth.JWKSPayload()
}

func (s *Service) CreateUser(ctx context.Context, accessToken string, input CreateUserInput) (AuthenticatedUser, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return AuthenticatedUser{}, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return AuthenticatedUser{}, ErrForbidden
	}

	email := strings.ToLower(strings.TrimSpace(input.Email))
	username := strings.TrimSpace(input.Username)
	password := input.Password
	if email == "" || username == "" || password == "" {
		return AuthenticatedUser{}, ErrInvalidInput
	}

	hash, err := s.passwords.Hash(password)
	if err != nil {
		return AuthenticatedUser{}, fmt.Errorf("hash password: %w", err)
	}

	isActive := true
	if input.IsActive != nil {
		isActive = *input.IsActive
	}

	now := time.Now().UTC()
	user := User{
		ID:           tokenutil.NewID(),
		Email:        email,
		Username:     username,
		PasswordHash: hash,
		IsActive:     isActive,
		Roles:        cloneOrEmpty(input.Roles),
		Permissions:  cloneOrEmpty(input.Permissions),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.SaveUser(ctx, user); err != nil {
		return AuthenticatedUser{}, fmt.Errorf("save user: %w", err)
	}

	s.recordAuditEvent(ctx, claims.Subject, "user_created", map[string]any{
		"created_user_id": user.ID,
		"email":           user.Email,
		"username":        user.Username,
	})

	return AuthenticatedUser{
		ID:          user.ID,
		Email:       user.Email,
		Username:    user.Username,
		IsActive:    user.IsActive,
		Roles:       cloneOrEmpty(user.Roles),
		Permissions: cloneOrEmpty(user.Permissions),
	}, nil
}

func (s *Service) ListUsers(ctx context.Context, accessToken string) ([]UserView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return nil, ErrForbidden
	}

	users, err := s.users.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]UserView, 0, len(users))
	for _, user := range users {
		out = append(out, UserView{
			ID:          user.ID,
			Email:       user.Email,
			Username:    user.Username,
			IsActive:    user.IsActive,
			Roles:       cloneOrEmpty(user.Roles),
			Permissions: cloneOrEmpty(user.Permissions),
			CreatedAt:   user.CreatedAt,
			UpdatedAt:   user.UpdatedAt,
		})
	}

	return out, nil
}

func (s *Service) SetUserActive(ctx context.Context, accessToken string, input SetUserActiveInput) (UserView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return UserView{}, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return UserView{}, ErrForbidden
	}
	if strings.TrimSpace(input.UserID) == "" {
		return UserView{}, ErrInvalidInput
	}

	user, err := s.users.FindUserByID(ctx, input.UserID)
	if err != nil {
		return UserView{}, ErrInvalidInput
	}

	user.IsActive = input.IsActive
	user.UpdatedAt = time.Now().UTC()
	if err := s.users.SaveUser(ctx, user); err != nil {
		return UserView{}, fmt.Errorf("save updated user: %w", err)
	}

	s.recordAuditEvent(ctx, claims.Subject, "user_status_changed", map[string]any{
		"target_user_id": input.UserID,
		"is_active":      input.IsActive,
	})

	return UserView{
		ID:          user.ID,
		Email:       user.Email,
		Username:    user.Username,
		IsActive:    user.IsActive,
		Roles:       cloneOrEmpty(user.Roles),
		Permissions: cloneOrEmpty(user.Permissions),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}, nil
}

func (s *Service) SetUserAccess(ctx context.Context, accessToken string, input SetUserAccessInput) (UserView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return UserView{}, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return UserView{}, ErrForbidden
	}
	if strings.TrimSpace(input.UserID) == "" {
		return UserView{}, ErrInvalidInput
	}

	user, err := s.users.FindUserByID(ctx, input.UserID)
	if err != nil {
		return UserView{}, ErrInvalidInput
	}

	user.Roles = cloneOrEmpty(input.Roles)
	user.Permissions = cloneOrEmpty(input.Permissions)
	user.UpdatedAt = time.Now().UTC()
	if err := s.users.SaveUser(ctx, user); err != nil {
		return UserView{}, fmt.Errorf("save updated user access: %w", err)
	}

	s.recordAuditEvent(ctx, claims.Subject, "user_access_changed", map[string]any{
		"target_user_id": input.UserID,
		"roles":          user.Roles,
		"permissions":    user.Permissions,
	})

	return UserView{
		ID:          user.ID,
		Email:       user.Email,
		Username:    user.Username,
		IsActive:    user.IsActive,
		Roles:       cloneOrEmpty(user.Roles),
		Permissions: cloneOrEmpty(user.Permissions),
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
	}, nil
}

func (s *Service) CreateClient(ctx context.Context, accessToken string, input CreateClientInput) (ClientView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return ClientView{}, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return ClientView{}, ErrForbidden
	}
	if s.clients == nil {
		return ClientView{}, ErrInvalidInput
	}

	name := strings.TrimSpace(input.Name)
	audience := strings.TrimSpace(input.Audience)
	secret := input.Secret
	if name == "" || audience == "" || secret == "" {
		return ClientView{}, ErrInvalidInput
	}

	hash, err := s.passwords.Hash(secret)
	if err != nil {
		return ClientView{}, fmt.Errorf("hash client secret: %w", err)
	}

	isActive := true
	if input.IsActive != nil {
		isActive = *input.IsActive
	}

	now := time.Now().UTC()
	client := Client{
		ID:          tokenutil.NewID(),
		Name:        name,
		Audience:    audience,
		SecretHash:  hash,
		IsActive:    isActive,
		Scopes:      cloneOrEmpty(input.Scopes),
		Roles:       cloneOrEmpty(input.Roles),
		Permissions: cloneOrEmpty(input.Permissions),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := s.clients.SaveClient(ctx, client); err != nil {
		return ClientView{}, fmt.Errorf("save client: %w", err)
	}

	s.recordAuditEvent(ctx, claims.Subject, "client_created", map[string]any{
		"client_id": client.ID,
		"audience":  client.Audience,
		"name":      client.Name,
	})

	return toClientView(client), nil
}

func (s *Service) ListClients(ctx context.Context, accessToken string) ([]ClientView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "users:manage") {
		return nil, ErrForbidden
	}
	if s.clients == nil {
		return nil, ErrInvalidInput
	}

	clients, err := s.clients.ListClients(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]ClientView, 0, len(clients))
	for _, client := range clients {
		out = append(out, toClientView(client))
	}

	return out, nil
}

func (s *Service) ListMySessions(ctx context.Context, accessToken string) ([]SessionView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return nil, ErrUnauthorized
	}

	sessions, err := s.sessions.ListSessionsByUserID(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}

	return toSessionViews(sessions), nil
}

func (s *Service) ListSessions(ctx context.Context, accessToken string) ([]SessionView, error) {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return nil, ErrUnauthorized
	}
	if !hasRole(claims.Roles, "admin") && !hasPermission(claims.Permissions, "sessions:manage") {
		return nil, ErrForbidden
	}

	sessions, err := s.sessions.ListSessions(ctx)
	if err != nil {
		return nil, err
	}

	return toSessionViews(sessions), nil
}

func (s *Service) RevokeSessionByID(ctx context.Context, accessToken, sessionID string) error {
	claims, err := s.accessAuth.Verify(accessToken)
	if err != nil {
		return ErrUnauthorized
	}

	session, err := s.sessions.FindSessionByID(ctx, sessionID)
	if err != nil {
		return ErrInvalidInput
	}

	canManageAny := hasRole(claims.Roles, "admin") || hasPermission(claims.Permissions, "sessions:manage")
	if !canManageAny && session.UserID != claims.Subject {
		return ErrForbidden
	}

	if err := s.sessions.RevokeSession(ctx, sessionID); err != nil {
		return err
	}

	s.recordAuditEvent(ctx, claims.Subject, "session_revoked", map[string]any{
		"session_id":      sessionID,
		"target_user_id":  session.UserID,
		"performed_by_id": claims.Subject,
	})

	return nil
}

func effectiveAudience(audience string) []string {
	if strings.TrimSpace(audience) == "" {
		return []string{"default"}
	}

	return []string{strings.TrimSpace(audience)}
}

func (s *Service) resolveAudience(ctx context.Context, audience string) (string, error) {
	value := strings.TrimSpace(audience)
	if value == "" {
		return "default", nil
	}
	if s.clients == nil {
		return "", ErrInvalidInput
	}

	client, err := s.clients.FindClientByAudience(ctx, value)
	if err != nil || !client.IsActive {
		return "", ErrInvalidInput
	}

	return client.Audience, nil
}

func hasRole(roles []string, role string) bool {
	return slices.Contains(roles, role)
}

func hasPermission(permissions []string, permission string) bool {
	return slices.Contains(permissions, permission)
}

func cloneOrEmpty(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	return append([]string(nil), values...)
}

func toSessionViews(sessions []Session) []SessionView {
	out := make([]SessionView, 0, len(sessions))
	for _, session := range sessions {
		out = append(out, SessionView{
			ID:        session.ID,
			UserID:    session.UserID,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			RevokedAt: session.RevokedAt,
		})
	}

	return out
}

func toClientView(client Client) ClientView {
	return ClientView{
		ID:          client.ID,
		Name:        client.Name,
		Audience:    client.Audience,
		IsActive:    client.IsActive,
		Scopes:      cloneOrEmpty(client.Scopes),
		Roles:       cloneOrEmpty(client.Roles),
		Permissions: cloneOrEmpty(client.Permissions),
		CreatedAt:   client.CreatedAt,
		UpdatedAt:   client.UpdatedAt,
	}
}

func buildScopes(permissions []string) []string {
	return cloneOrEmpty(permissions)
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

func (s *Service) recordAuditEvent(ctx context.Context, userID, eventType string, metadata map[string]any) {
	if s.audit == nil {
		return
	}

	requestMetadata := RequestMetadataFromContext(ctx)
	if metadata == nil {
		metadata = map[string]any{}
	}
	if requestMetadata.RequestID != "" {
		metadata["request_id"] = requestMetadata.RequestID
	}
	if requestMetadata.ClientIP != "" {
		metadata["client_ip"] = requestMetadata.ClientIP
	}
	if requestMetadata.UserAgent != "" {
		metadata["user_agent"] = requestMetadata.UserAgent
	}

	_ = s.audit.RecordAuditEvent(ctx, AuditEvent{
		ID:        tokenutil.NewID(),
		UserID:    userID,
		EventType: eventType,
		Metadata:  metadata,
		CreatedAt: time.Now().UTC(),
	})
}
