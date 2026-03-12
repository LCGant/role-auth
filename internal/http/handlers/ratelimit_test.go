package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/store"
)

func TestRedisOptionsParsesURL(t *testing.T) {
	opts := redisOptions("redis://:secret@redis.example:6380/2")
	if opts.Addr != "redis.example:6380" {
		t.Fatalf("expected parsed addr redis.example:6380, got %q", opts.Addr)
	}
	if opts.Password != "secret" {
		t.Fatalf("expected parsed password, got %q", opts.Password)
	}
	if opts.DB != 2 {
		t.Fatalf("expected parsed db=2, got %d", opts.DB)
	}
}

func TestRedisOptionsFallsBackToAddr(t *testing.T) {
	opts := redisOptions("redis:6379")
	if opts.Addr != "redis:6379" {
		t.Fatalf("expected addr fallback, got %q", opts.Addr)
	}
}

func TestRateLimiterCapsTrackedEntries(t *testing.T) {
	rl := NewRateLimiter(10, time.Minute)
	rl.maxEntries = 2

	if !rl.Allow("k1") {
		t.Fatalf("expected first key to pass")
	}
	if !rl.Allow("k2") {
		t.Fatalf("expected second key to pass")
	}
	if !rl.Allow("k3") {
		t.Fatalf("expected third key to pass after eviction")
	}
	if got := len(rl.limits); got > 2 {
		t.Fatalf("expected limits map capped at 2 entries, got %d", got)
	}
}

func TestRateLimitAppliesToInternalPaths(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	cfg := config.Config{}
	cfg.Security.InternalToken = "internal-secret"
	mw := RateLimit(rl, cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req1.RemoteAddr = "198.51.100.10:1234"
	req1.Header.Set("X-Internal-Token", "internal-secret")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusOK {
		t.Fatalf("expected first request to pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req2.RemoteAddr = "198.51.100.10:1234"
	req2.Header.Set("X-Internal-Token", "internal-secret")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", rr2.Code)
	}
}

func TestRateLimitInternalKeyIgnoresClientIDWithoutValidToken(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	cfg := config.Config{}
	cfg.Security.InternalToken = "internal-secret"
	mw := RateLimit(rl, cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqA := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	reqA.RemoteAddr = "198.51.100.10:1234"
	reqA.Header.Set("X-Internal-Token", "invalid-a")
	reqA.Header.Set("X-Client-Id", "client-a")
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA)
	if rrA.Code != http.StatusOK {
		t.Fatalf("expected first invalid-token request to pass, got %d", rrA.Code)
	}

	reqB := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	reqB.RemoteAddr = "198.51.100.10:1234"
	reqB.Header.Set("X-Internal-Token", "invalid-b")
	reqB.Header.Set("X-Client-Id", "client-b")
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusTooManyRequests {
		t.Fatalf("expected varying client ids to be ignored before auth, got %d", rrB.Code)
	}
}

func TestRateLimitInternalKeyUsesClientIDAfterValidToken(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	cfg := config.Config{}
	cfg.Security.InternalToken = "internal-secret"
	mw := RateLimit(rl, cfg)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	reqA := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	reqA.RemoteAddr = "198.51.100.10:1234"
	reqA.Header.Set("X-Internal-Token", "internal-secret")
	reqA.Header.Set("X-Client-Id", "client-a")
	rrA := httptest.NewRecorder()
	handler.ServeHTTP(rrA, reqA)
	if rrA.Code != http.StatusOK {
		t.Fatalf("expected first authorized client request to pass, got %d", rrA.Code)
	}

	reqB := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	reqB.RemoteAddr = "198.51.100.10:1234"
	reqB.Header.Set("X-Internal-Token", "internal-secret")
	reqB.Header.Set("X-Client-Id", "client-b")
	rrB := httptest.NewRecorder()
	handler.ServeHTTP(rrB, reqB)
	if rrB.Code != http.StatusOK {
		t.Fatalf("expected explicit client ids to isolate authorized internal callers, got %d", rrB.Code)
	}
}

func TestEmailVerificationRequestUsesForgotLimiter(t *testing.T) {
	cfg := baseConfig()
	cfg.Security.ForgotLimit = config.RateLimitConfig{Requests: 1, Window: time.Minute}
	cfg.Mail.OutboxDir = t.TempDir()
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-1",
		Email:         "u@example.com",
		Username:      "u",
		Status:        "pending_verification",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	req1 := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{"email":"u@example.com"}`))
	req1.RemoteAddr = "198.51.100.10:1234"
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Client-Family", "cli")
	rr1 := httptest.NewRecorder()
	srv.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("expected first request to pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{"email":"u@example.com"}`))
	req2.RemoteAddr = "198.51.100.10:1234"
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Client-Family", "cli")
	rr2 := httptest.NewRecorder()
	srv.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second request to be rate limited, got %d", rr2.Code)
	}
}

func TestEmailVerificationRequestRateLimitsByEmailAcrossIPs(t *testing.T) {
	cfg := baseConfig()
	cfg.Security.ForgotLimit = config.RateLimitConfig{Requests: 10, Window: time.Minute}
	cfg.Mail.OutboxDir = t.TempDir()
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-1",
		Email:         "u@example.com",
		Username:      "u",
		Status:        "pending_verification",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	req1 := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{"email":"u@example.com"}`))
	req1.RemoteAddr = "198.51.100.10:1234"
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-Client-Family", "cli")
	rr1 := httptest.NewRecorder()
	srv.ServeHTTP(rr1, req1)
	if rr1.Code != http.StatusAccepted {
		t.Fatalf("expected first request to pass, got %d", rr1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/email/verify/request", strings.NewReader(`{"email":"u@example.com"}`))
	req2.RemoteAddr = "198.51.100.11:1234"
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-Client-Family", "cli")
	rr2 := httptest.NewRecorder()
	srv.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusAccepted {
		t.Fatalf("expected second request to return generic accepted response, got %d", rr2.Code)
	}

	entries, err := os.ReadDir(cfg.Mail.OutboxDir)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected a single verification email to be written, got %d", len(entries))
	}
}
