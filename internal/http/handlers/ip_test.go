package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/LCGant/role-auth/internal/config"
)

func TestClientIPTrustedProxyRightToLeft(t *testing.T) {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			TrustProxyHeader:  true,
			ProxyTrustedCIDRs: mustCIDRs(t, "10.0.0.0/8"),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1, 203.0.113.9")

	got := clientIP(req, cfg)
	if got != "203.0.113.9" {
		t.Fatalf("expected first untrusted hop from right, got %q", got)
	}
}

func TestClientIPIgnoresXFFWhenProxyUntrusted(t *testing.T) {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			TrustProxyHeader:  true,
			ProxyTrustedCIDRs: mustCIDRs(t, "10.0.0.0/8"),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.9")

	got := clientIP(req, cfg)
	if got != "198.51.100.10" {
		t.Fatalf("expected remote address, got %q", got)
	}
}

func mustCIDRs(t *testing.T, cidrs ...string) []netipPrefix {
	t.Helper()
	out := make([]netipPrefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := parsePrefix(c)
		if err != nil {
			t.Fatalf("parse cidr %s: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

type netipPrefix = netip.Prefix

func parsePrefix(cidr string) (netipPrefix, error) { return netip.ParsePrefix(cidr) }
