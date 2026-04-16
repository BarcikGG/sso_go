package token

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const refreshTokenSize = 32

func NewRefreshToken() (plain string, hashed string, err error) {
	buf := make([]byte, refreshTokenSize)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate refresh token: %w", err)
	}

	plain = base64.RawURLEncoding.EncodeToString(buf)
	hashed = HashRefreshToken(plain)

	return plain, hashed, nil
}

func HashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
