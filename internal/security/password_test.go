package security

import "testing"

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
