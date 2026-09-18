package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

func parseTrustedProxies(raw string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	if strings.TrimSpace(raw) == "" {
		return networks, nil
	}
	for _, part := range strings.Split(raw, ",") {
		_, network, err := net.ParseCIDR(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid SSO_TRUSTED_PROXY_CIDRS: %w", err)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

func (s *Server) trustedProxy(ip net.IP) bool {
	for _, network := range s.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Server) clientIP(r *http.Request) string {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := net.ParseIP(remote)
	if ip == nil || !s.trustedProxy(ip) {
		return remote
	}
	// Walk the proxy chain backwards. The first untrusted address is the client.
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		candidate := net.ParseIP(strings.TrimSpace(forwarded[i]))
		if candidate == nil {
			break
		}
		ip = candidate
		if !s.trustedProxy(ip) {
			break
		}
	}
	return ip.String()
}

func (s *Server) allowAttempt(r *http.Request, scope, value string, limit int, window time.Duration) bool {
	return s.limits.Allow(r.Context(), scope, value, limit, window)
}
