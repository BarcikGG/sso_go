package auth

import "time"

type User struct {
	ID           string
	Email        string
	Username     string
	PasswordHash string
	IsActive     bool
	Roles        []string
	Permissions  []string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Session struct {
	ID                  string
	UserID              string
	FamilyID            string
	ParentSessionID     string
	ReplacedBySessionID string
	RefreshTokenHash    string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	UsedAt              *time.Time
	RevokedAt           *time.Time
}

type SessionView struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	FamilyID            string     `json:"family_id"`
	ParentSessionID     string     `json:"parent_session_id,omitempty"`
	ReplacedBySessionID string     `json:"replaced_by_session_id,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	UsedAt              *time.Time `json:"used_at,omitempty"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type AuthenticatedUser struct {
	ID          string   `json:"id"`
	SubjectType string   `json:"subject_type"`
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	IsActive    bool     `json:"is_active"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Scopes      []string `json:"scopes"`
	Audience    []string `json:"audience"`
}

type UserView struct {
	ID          string    `json:"id"`
	Email       string    `json:"email"`
	Username    string    `json:"username"`
	IsActive    bool      `json:"is_active"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type LoginInput struct {
	Login    string
	Password string
	Audience string
}

type CreateUserInput struct {
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IsActive    *bool    `json:"is_active"`
}

type SetUserActiveInput struct {
	UserID   string `json:"user_id"`
	IsActive bool   `json:"is_active"`
}

type SetUserAccessInput struct {
	UserID      string   `json:"user_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type Client struct {
	ID          string
	Name        string
	Audience    string
	SecretHash  string
	IsActive    bool
	Scopes      []string
	Roles       []string
	Permissions []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ClientView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Audience    string    `json:"audience"`
	IsActive    bool      `json:"is_active"`
	Scopes      []string  `json:"scopes"`
	Roles       []string  `json:"roles"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateClientInput struct {
	Name        string   `json:"name"`
	Audience    string   `json:"audience"`
	Secret      string   `json:"secret"`
	Scopes      []string `json:"scopes"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IsActive    *bool    `json:"is_active"`
}

type ClientTokenInput struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Audience     string `json:"audience"`
}
