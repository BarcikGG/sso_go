package httpapi

import (
	"net/http/httptest"
	"testing"

	"github.com/endl/sso_go/internal/service"
)

func TestRedirectRegistrationRequiresExactSecureURIs(t *testing.T) {
	valid := [][]string{{"https://app.example/callback"}, {"http://localhost:8081/callback", "https://app.example/other"}}
	for _, v := range valid {
		if err := service.ValidateRedirects(v); err != nil {
			t.Fatalf("valid redirects rejected: %v", err)
		}
	}
	invalid := [][]string{{}, {"https://app.example/*"}, {"https://app.example/callback#frag"}, {"http://app.example/callback"}, {"https://app.example/callback", "https://app.example/callback"}, {"//app.example/callback"}}
	for _, v := range invalid {
		if err := service.ValidateRedirects(v); err == nil {
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

func TestClientIPTrustsOnlyConfiguredProxyChain(t *testing.T) {
	proxies, err := parseTrustedProxies("10.0.0.0/8,192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{trustedProxies: proxies}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "203.0.113.8:4567"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := s.clientIP(r); got != "203.0.113.8" {
		t.Fatalf("untrusted sender controlled client IP: %s", got)
	}
	r.RemoteAddr = "10.1.2.3:4567"
	r.Header.Set("X-Forwarded-For", "198.51.100.9, 203.0.113.8, 192.0.2.4")
	if got := s.clientIP(r); got != "203.0.113.8" {
		t.Fatalf("wrong first untrusted hop: %s", got)
	}
	if _, err := parseTrustedProxies("not-a-network"); err == nil {
		t.Fatal("invalid trusted proxy network accepted")
	}
}
