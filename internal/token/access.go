package token

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AccessClaims struct {
	Subject     string
	Audience    []string
	SessionID   string
	Roles       []string
	Permissions []string
	ExpiresIn   time.Duration
}

type VerifiedAccessClaims struct {
	Issuer      string
	Subject     string
	Audience    []string
	SessionID   string
	Roles       []string
	Permissions []string
	ExpiresAt   time.Time
}

type AccessSigner struct {
	issuer     string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

type accessHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
}

type accessPayload struct {
	Issuer      string   `json:"iss"`
	Subject     string   `json:"sub"`
	Audience    []string `json:"aud"`
	SessionID   string   `json:"sid"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	IssuedAt    int64    `json:"iat"`
	NotBefore   int64    `json:"nbf"`
	ExpiresAt   int64    `json:"exp"`
}

type jwkDocument struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

func NewAccessSigner(issuer, secret string) (*AccessSigner, error) {
	if secret == "" {
		return nil, fmt.Errorf("token signing key is empty")
	}

	seed := sha256.Sum256([]byte(secret))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyIDHash := sha256.Sum256(publicKey)

	return &AccessSigner{
		issuer:     issuer,
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      hex.EncodeToString(keyIDHash[:8]),
	}, nil
}

func (s *AccessSigner) Sign(claims AccessClaims) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(claims.ExpiresIn)

	headerJSON, err := json.Marshal(accessHeader{
		Algorithm: "EdDSA",
		Type:      "JWT",
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(accessPayload{
		Issuer:      s.issuer,
		Subject:     claims.Subject,
		Audience:    claims.Audience,
		SessionID:   claims.SessionID,
		Roles:       claims.Roles,
		Permissions: claims.Permissions,
		IssuedAt:    now.Unix(),
		NotBefore:   now.Unix(),
		ExpiresAt:   expiresAt.Unix(),
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("marshal payload: %w", err)
	}

	encodedHeader := base64.RawURLEncoding.EncodeToString(headerJSON)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := encodedHeader + "." + encodedPayload

	signature := ed25519.Sign(s.privateKey, []byte(signingInput))
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	return signingInput + "." + encodedSignature, expiresAt, nil
}

func (s *AccessSigner) Verify(token string) (VerifiedAccessClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return VerifiedAccessClaims{}, fmt.Errorf("invalid token format")
	}

	signingInput := parts[0] + "." + parts[1]

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return VerifiedAccessClaims{}, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(s.publicKey, []byte(signingInput), signature) {
		return VerifiedAccessClaims{}, fmt.Errorf("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return VerifiedAccessClaims{}, fmt.Errorf("decode payload: %w", err)
	}

	var payload accessPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return VerifiedAccessClaims{}, fmt.Errorf("unmarshal payload: %w", err)
	}

	now := time.Now().UTC()
	if payload.Issuer != s.issuer {
		return VerifiedAccessClaims{}, fmt.Errorf("invalid issuer")
	}
	if now.Unix() >= payload.ExpiresAt {
		return VerifiedAccessClaims{}, fmt.Errorf("token expired")
	}

	return VerifiedAccessClaims{
		Issuer:      payload.Issuer,
		Subject:     payload.Subject,
		Audience:    append([]string(nil), payload.Audience...),
		SessionID:   payload.SessionID,
		Roles:       append([]string(nil), payload.Roles...),
		Permissions: append([]string(nil), payload.Permissions...),
		ExpiresAt:   time.Unix(payload.ExpiresAt, 0).UTC(),
	}, nil
}

func (s *AccessSigner) JWKSPayload() (json.RawMessage, error) {
	doc := jwkDocument{
		Keys: []jwkKey{
			{
				Kty: "OKP",
				Kid: s.keyID,
				Crv: "Ed25519",
				X:   base64.RawURLEncoding.EncodeToString(s.publicKey),
				Alg: "EdDSA",
				Use: "sig",
			},
		},
	}

	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}

	return body, nil
}
