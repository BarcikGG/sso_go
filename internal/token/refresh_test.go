package token

import "testing"

func TestNewRefreshToken(t *testing.T) {
	t.Parallel()

	plain, hashed, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("create refresh token: %v", err)
	}
	if plain == "" {
		t.Fatal("expected plain token")
	}
	if hashed == "" {
		t.Fatal("expected hashed token")
	}
	if got := HashRefreshToken(plain); got != hashed {
		t.Fatalf("expected deterministic hash, got %q want %q", got, hashed)
	}
}
