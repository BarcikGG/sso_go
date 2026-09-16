package provider

import "testing"

func TestRedirectRegistrationRequiresExactSecureURIs(t *testing.T) {
	valid := [][]string{{"https://app.example/callback"}, {"http://localhost:8081/callback", "https://app.example/other"}}
	for _, v := range valid {
		if err := validateRedirects(v); err != nil {
			t.Fatalf("valid redirects rejected: %v", err)
		}
	}
	invalid := [][]string{{}, {"https://app.example/*"}, {"https://app.example/callback#frag"}, {"http://app.example/callback"}, {"https://app.example/callback", "https://app.example/callback"}, {"//app.example/callback"}}
	for _, v := range invalid {
		if err := validateRedirects(v); err == nil {
			t.Fatalf("invalid redirects accepted: %v", v)
		}
	}
}

func TestLoginReturnPathRejectsExternalTargets(t *testing.T) {
	if got := safeNext("/authorize?client_id=main_api"); got != "/authorize?client_id=main_api" {
		t.Fatal(got)
	}
	for _, v := range []string{"//other.example", "/\\other.example", "https://other.example", "/authorize\\other.example"} {
		if got := safeNext(v); got != "/projects" {
			t.Fatalf("unsafe target %q accepted as %q", v, got)
		}
	}
}
