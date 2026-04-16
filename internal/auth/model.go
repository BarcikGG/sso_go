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
	ID               string
	UserID           string
	RefreshTokenHash string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	RevokedAt        *time.Time
}

type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type AuthenticatedUser struct {
	ID          string   `json:"id"`
	Email       string   `json:"email"`
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type LoginInput struct {
	Login    string
	Password string
	Audience string
}
