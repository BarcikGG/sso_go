package domain

import "time"

type AccessTokenClaims struct {
	Issuer      string
	Subject     string
	Audience    []string
	SessionID   string
	Roles       []string
	Permissions []string
	ExpiresAt   time.Time
	IssuedAt    time.Time
	NotBefore   time.Time
	TokenID     string
}
