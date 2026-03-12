package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/LCGant/role-auth/internal/config"
)

func TestPublicMutationOriginAllowed(t *testing.T) {
	cfg := config.Config{
		HTTP: config.HTTPConfig{
			CORSOrigins: []string{"https://app.example.com"},
		},
	}

	t.Run("allows matching origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Origin", "https://app.example.com")
		if !publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected origin to be allowed")
		}
	})

	t.Run("rejects mismatched origin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		if publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected origin to be rejected")
		}
	})

	t.Run("allows referer fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Referer", "https://app.example.com/login")
		if !publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected referer origin to be allowed")
		}
	})

	t.Run("allows explicit api client without origin or referer", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("X-Client-Family", "mobile_app")
		if !publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected explicit api client to be allowed")
		}
	})

	t.Run("rejects missing origin and referer without explicit api client signal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		if publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected request without browser headers to be rejected")
		}
	})

	t.Run("rejects missing origin and referer when session cookie is present", func(t *testing.T) {
		cfg := cfg
		cfg.Cookie.Name = "session_id"
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: "session"})
		if publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected request with session cookie and no browser headers to be rejected")
		}
	})

	t.Run("falls back to public url origin when cors list is empty", func(t *testing.T) {
		cfg := config.Config{
			HTTP: config.HTTPConfig{
				PublicURL: "https://auth.example.com/auth",
			},
		}
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Origin", "https://auth.example.com")
		if !publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected public url origin to be allowed when cors list is empty")
		}
	})

	t.Run("rejects mismatched browser origin even with api client signal", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		req.Header.Set("X-Client-Family", "mobile_app")
		if publicMutationOriginAllowed(req, cfg) {
			t.Fatalf("expected mismatched origin to win over api client hint")
		}
	})
}
