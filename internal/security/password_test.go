package security

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestLegacyBcryptPasswordCanBeVerified(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("legacy-password-123"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	encoded := strings.Replace(string(hash), "$2a$", "$2b$", 1)
	if !IsValidLegacyBcrypt(encoded) {
		t.Fatal("generated legacy bcrypt hash was not recognized")
	}
	if IsValidLegacyBcrypt("$2b$malformed") {
		t.Fatal("malformed legacy bcrypt hash was accepted")
	}
	hasher := NewPasswordHasher()
	if ok, err := hasher.Verify("legacy-password-123", encoded); err != nil || !ok {
		t.Fatalf("legacy bcrypt password rejected: %v", err)
	}
	if ok, err := hasher.Verify("wrong-password", encoded); err != nil || ok {
		t.Fatalf("wrong legacy password accepted: %v", err)
	}
}

func TestPasswordHasherHashAndVerify(t *testing.T) {
	t.Parallel()

	hasher := NewPasswordHasher()
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := hasher.Verify("correct horse battery staple", hash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !ok {
		t.Fatal("expected password verification to succeed")
	}
}

func TestPasswordHasherRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	hasher := NewPasswordHasher()
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := hasher.Verify("wrong password", hash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if ok {
		t.Fatal("expected password verification to fail")
	}
}
