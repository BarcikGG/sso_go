package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonVariant = "argon2id"
	argonVersion = 19
	saltLength   = 16
	keyLength    = 32
)

type PasswordHasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		memory:      64 * 1024,
		iterations:  3,
		parallelism: 2,
		keyLength:   keyLength,
	}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password is empty")
	}

	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, h.iterations, h.memory, h.parallelism, h.keyLength)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argonVariant,
		argonVersion,
		h.memory,
		h.iterations,
		h.parallelism,
		encodedSalt,
		encodedHash,
	), nil
}

func (h *PasswordHasher) Verify(password, encoded string) (bool, error) {
	params, salt, hash, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	comparison := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)
	if subtle.ConstantTimeCompare(hash, comparison) == 1 {
		return true, nil
	}

	return false, nil
}

func decodeHash(encoded string) (*PasswordHasher, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != argonVariant {
		return nil, nil, nil, fmt.Errorf("unexpected hash variant: %s", parts[1])
	}

	versionRaw := strings.TrimPrefix(parts[2], "v=")
	version, err := strconv.Atoi(versionRaw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse version: %w", err)
	}
	if version != argonVersion {
		return nil, nil, nil, fmt.Errorf("unsupported argon version: %d", version)
	}

	params := &PasswordHasher{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism); err != nil {
		return nil, nil, nil, fmt.Errorf("parse hash params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode hash: %w", err)
	}

	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}
