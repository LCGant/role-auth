//go:build integration

package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/http/handlers"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store/postgres"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func TestRegisterLoginLogoutFlow(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client
	jar := env.client.Jar

	registerAndVerify(t, env, "alice@example.com", "alice", "StrongP@ss1")

	body := `{"identifier":"alice@example.com","password":"StrongP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", body, http.StatusOK, "")
	csrf := readCookie(jar, baseURL, "csrf_token")
	if csrf == "" {
		t.Fatalf("csrf cookie missing")
	}
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d err=%v", res.StatusCode, err)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d err=%v", res.StatusCode, err)
	}
	res.Body.Close()
}

func TestRegisterRequiresEmailVerificationBeforeLogin(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	body := `{"email":"verifyme@example.com","username":"verifyme","password":"StrongP@ss1"}`
	res := postJSON(t, client, baseURL+"/register", body, http.StatusCreated, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/login", `{"identifier":"verifyme@example.com","password":"StrongP@ss1"}`, http.StatusUnauthorized, "")
	res.Body.Close()

	verifyEmail(t, env, "verifyme@example.com")

	res = postJSON(t, client, baseURL+"/login", `{"identifier":"verifyme@example.com","password":"StrongP@ss1"}`, http.StatusOK, "")
	res.Body.Close()
}

func TestMFAFlow(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "bob@example.com", "bob", "AnotherP@ss1")

	loginBody := `{"identifier":"bob@example.com","password":"AnotherP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	csrf := readCookie(client.Jar, baseURL, "csrf_token")
	if csrf == "" {
		t.Fatalf("csrf cookie missing")
	}
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mfa/totp/setup", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("totp setup status=%d err=%v", status(res), err)
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)
	if setupResp.Secret == "" {
		t.Fatalf("totp secret missing")
	}

	code, err := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"code":"%s"}`, code)
	res = postJSON(t, client, baseURL+"/mfa/totp/verify", verifyBody, http.StatusOK, csrf)
	var verifyResp struct {
		BackupCodes []string `json:"backup_codes"`
	}
	decodeBody(t, res, &verifyResp)
	if len(verifyResp.BackupCodes) == 0 {
		t.Fatalf("backup codes missing")
	}

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/login", loginBody, http.StatusUnauthorized, "")
	var mfaResp map[string]any
	decodeBody(t, res, &mfaResp)
	if mfaResp["mfa_required"] != true {
		t.Fatalf("expected mfa_required response")
	}

	code, _ = security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	loginWithTOTP := fmt.Sprintf(`{"identifier":"bob@example.com","password":"AnotherP@ss1","totp_code":"%s"}`, code)
	res = postJSON(t, client, baseURL+"/login", loginWithTOTP, http.StatusOK, "")
	csrf = readCookie(client.Jar, baseURL, "csrf_token")
	if csrf == "" {
		t.Fatalf("csrf missing after totp login")
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout after totp status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	backup := verifyResp.BackupCodes[0]
	loginWithBackup := fmt.Sprintf(`{"identifier":"bob@example.com","password":"AnotherP@ss1","backup_code":"%s"}`, backup)
	res = postJSON(t, client, baseURL+"/login", loginWithBackup, http.StatusOK, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/login", loginWithBackup, http.StatusUnauthorized, "")
	res.Body.Close()
}

func TestPasswordResetFlow(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "carol@example.com", "carol", "ResetP@ss1")

	body := `{"email":"carol@example.com"}`
	res := postJSON(t, client, baseURL+"/password/forgot", body, http.StatusOK, "")
	res.Body.Close()
	token := waitForOutboxToken(t, env.cfg.Mail.OutboxDir, "reset-", "carol@example.com")

	resetBody := fmt.Sprintf(`{"token":"%s","new_password":"NewResetP@ss2"}`, token)
	res = postJSON(t, client, baseURL+"/password/reset", resetBody, http.StatusOK, "")
	res.Body.Close()

	oldLogin := `{"identifier":"carol@example.com","password":"ResetP@ss1"}`
	res = postJSON(t, client, baseURL+"/login", oldLogin, http.StatusUnauthorized, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/password/reset", resetBody, http.StatusUnauthorized, "")
	res.Body.Close()

	newLogin := `{"identifier":"carol@example.com","password":"NewResetP@ss2"}`
	res = postJSON(t, client, baseURL+"/login", newLogin, http.StatusOK, "")
	res.Body.Close()
}

func TestPasswordResetInvalidatesOlderPendingTokens(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "reset-old@example.com", "resetold", "ResetP@ss1")

	first, err := env.svc.StartPasswordReset(context.Background(), "reset-old@example.com", "127.0.0.1")
	if err != nil || first == "" {
		t.Fatalf("start first reset: %v", err)
	}
	second, err := env.svc.StartPasswordReset(context.Background(), "reset-old@example.com", "127.0.0.1")
	if err != nil || second == "" {
		t.Fatalf("start second reset: %v", err)
	}

	res := postJSON(t, client, baseURL+"/password/reset", fmt.Sprintf(`{"token":"%s","new_password":"AnotherP@ss2"}`, first), http.StatusUnauthorized, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/password/reset", fmt.Sprintf(`{"token":"%s","new_password":"AnotherP@ss2"}`, second), http.StatusOK, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/password/reset", fmt.Sprintf(`{"token":"%s","new_password":"ThirdP@ss3"}`, second), http.StatusUnauthorized, "")
	res.Body.Close()
}

func TestLockoutFlow(t *testing.T) {
	envOverrides := map[string]string{
		"LOCKOUT_MAX_ATTEMPTS": "3",
		"LOCKOUT_WINDOW":       "2s",
		"LOCKOUT_BLOCK_FOR":    "2s",
	}
	env := startTestEnv(t, envOverrides)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "dave@example.com", "dave", "LockP@ss1")

	badLogin := `{"identifier":"dave@example.com","password":"wrong"}`
	var res *http.Response
	for i := 0; i < 3; i++ {
		res = postJSON(t, client, baseURL+"/login", badLogin, http.StatusUnauthorized, "")
		res.Body.Close()
	}
	res = postJSON(t, client, baseURL+"/login", badLogin, http.StatusTooManyRequests, "")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected lockout status 429, got %d", res.StatusCode)
	}
	res.Body.Close()
	time.Sleep(3 * time.Second)
	goodLogin := `{"identifier":"dave@example.com","password":"LockP@ss1"}`
	res = postJSON(t, client, baseURL+"/login", goodLogin, http.StatusOK, "")
	res.Body.Close()
}

func TestCSRFProtection(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "eve@example.com", "eve", "CsrfP@ss1")

	loginBody := `{"identifier":"eve@example.com","password":"CsrfP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	csrf := readCookie(client.Jar, baseURL, "csrf_token")
	res.Body.Close()
	if csrf == "" {
		t.Fatalf("csrf missing")
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("logout without csrf failed: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf, got %d", res.StatusCode)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout with csrf status=%d err=%v", status(res), err)
	}
	res.Body.Close()
}

func TestBackupRegenerateInvalidatesOld(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "frank@example.com", "frank", "BackupP@ss1")

	loginBody := `{"identifier":"frank@example.com","password":"BackupP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	csrf := readCookie(client.Jar, baseURL, "csrf_token")
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mfa/totp/setup", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("setup totp status=%d err=%v", status(res), err)
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)

	code, err := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"code":"%s"}`, code)
	res = postJSON(t, client, baseURL+"/mfa/totp/verify", verifyBody, http.StatusOK, csrf)
	var verifyResp struct {
		BackupCodes []string `json:"backup_codes"`
	}
	decodeBody(t, res, &verifyResp)
	if len(verifyResp.BackupCodes) == 0 {
		t.Fatalf("backup codes missing")
	}
	oldBackup := verifyResp.BackupCodes[0]

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/mfa/backup/regenerate", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("regenerate status=%d err=%v", status(res), err)
	}
	var regenResp struct {
		BackupCodes []string `json:"backup_codes"`
	}
	decodeBody(t, res, &regenResp)
	if len(regenResp.BackupCodes) == 0 {
		t.Fatalf("new backup codes missing")
	}
	newBackup := regenResp.BackupCodes[0]

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	oldBackupLogin := fmt.Sprintf(`{"identifier":"frank@example.com","password":"BackupP@ss1","backup_code":"%s"}`, oldBackup)
	res = postJSON(t, client, baseURL+"/login", oldBackupLogin, http.StatusUnauthorized, "")
	res.Body.Close()

	newBackupLogin := fmt.Sprintf(`{"identifier":"frank@example.com","password":"BackupP@ss1","backup_code":"%s"}`, newBackup)
	res = postJSON(t, client, baseURL+"/login", newBackupLogin, http.StatusOK, "")
	res.Body.Close()
}

func TestSessionExpiryAndResetRevokesSessions(t *testing.T) {
	env := startTestEnv(t, map[string]string{"SESSION_TTL": "1s"})
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "gina@example.com", "gina", "ShortTTL1!")

	loginBody := `{"identifier":"gina@example.com","password":"ShortTTL1!"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	res.Body.Close()

	time.Sleep(2 * time.Second)
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("me request: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected expired session to be unauthorized, got %d", res.StatusCode)
	}
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	res.Body.Close()

	token, err := env.svc.StartPasswordReset(context.Background(), "gina@example.com", "127.0.0.1")
	if err != nil || token == "" {
		t.Fatalf("start reset: %v", err)
	}
	resetBody := fmt.Sprintf(`{"token":"%s","new_password":"ShortTTL2!"}`, token)
	res = postJSON(t, client, baseURL+"/password/reset", resetBody, http.StatusOK, "")
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("me after reset: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected session revoked after reset, got %d", res.StatusCode)
	}
	res.Body.Close()

	newLogin := `{"identifier":"gina@example.com","password":"ShortTTL2!"}`
	res = postJSON(t, client, baseURL+"/login", newLogin, http.StatusOK, "")
	res.Body.Close()
}

func TestTOTPRejectsStaleCode(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "henry@example.com", "henry", "TotpWin1!")

	loginBody := `{"identifier":"henry@example.com","password":"TotpWin1!"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	csrf := readCookie(client.Jar, baseURL, "csrf_token")
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mfa/totp/setup", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("setup totp status=%d err=%v", status(res), err)
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)

	code, err := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	verifyBody := fmt.Sprintf(`{"code":"%s"}`, code)
	res = postJSON(t, client, baseURL+"/mfa/totp/verify", verifyBody, http.StatusOK, csrf)
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	staleCode, _ := security.TOTPCode(setupResp.Secret, time.Now().Add(-5*time.Minute), 6, 30)
	staleLogin := fmt.Sprintf(`{"identifier":"henry@example.com","password":"TotpWin1!","totp_code":"%s"}`, staleCode)
	res = postJSON(t, client, baseURL+"/login", staleLogin, http.StatusUnauthorized, "")
	var mfaResp map[string]any
	decodeBody(t, res, &mfaResp)
	if mfaResp["mfa_required"] != true {
		t.Fatalf("expected mfa_required on stale code")
	}

	validCode, _ := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	validLogin := fmt.Sprintf(`{"identifier":"henry@example.com","password":"TotpWin1!","totp_code":"%s"}`, validCode)
	res = postJSON(t, client, baseURL+"/login", validLogin, http.StatusOK, "")
	res.Body.Close()
}

func TestRateLimitInMemory(t *testing.T) {
	env := startTestEnv(t, map[string]string{
		"RATE_LIMIT_REQUESTS": "2",
		"RATE_LIMIT_WINDOW":   "500ms",
	})
	baseURL := env.baseURL
	client := env.client

	limitedPath := "/__ratelimit"
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodGet, baseURL+limitedPath, nil)
		res, err := client.Do(req)
		if err != nil || res.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d status=%d err=%v", i, status(res), err)
		}
		res.Body.Close()
	}
	req, _ := http.NewRequest(http.MethodGet, baseURL+limitedPath, nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("rate limit request failed: %v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on rate limit, got %d", res.StatusCode)
	}
	res.Body.Close()
	time.Sleep(600 * time.Millisecond)
	req, _ = http.NewRequest(http.MethodGet, baseURL+limitedPath, nil)
	res, err = client.Do(req)
	if err != nil || res.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("after window status=%d err=%v", status(res), err)
	}
	res.Body.Close()
}

func TestRateLimitRedis(t *testing.T) {
	mr := mustStartMiniRedis(t)
	env := startTestEnv(t, map[string]string{
		"RATE_LIMIT_REQUESTS":  "1",
		"RATE_LIMIT_WINDOW":    "1s",
		"RATE_LIMIT_REDIS_URL": mr.Addr(),
		"LOCKOUT_REDIS_URL":    mr.Addr(),
		"LOCKOUT_MAX_ATTEMPTS": "5",
		"LOCKOUT_WINDOW":       "5s",
		"LOCKOUT_BLOCK_FOR":    "5s",
	})
	baseURL := env.baseURL
	client := env.client

	limitedPath := "/__ratelimit_redis"
	req, _ := http.NewRequest(http.MethodGet, baseURL+limitedPath, nil)
	res, err := client.Do(req)
	if err != nil || res.StatusCode == http.StatusTooManyRequests {
		t.Fatalf("redis first status=%d err=%v", status(res), err)
	}
	res.Body.Close()
	req, _ = http.NewRequest(http.MethodGet, baseURL+limitedPath, nil)
	res, err = client.Do(req)
	if err != nil {
		t.Fatalf("redis second err=%v", err)
	}
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 with redis limiter, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestForgotRateLimit(t *testing.T) {
	env := startTestEnv(t, map[string]string{
		"RATE_LIMIT_REQUESTS": "1",
		"RATE_LIMIT_WINDOW":   "2s",
	})
	baseURL := env.baseURL
	client := env.client

	body := `{"email":"forgot@example.com"}`
	res := postJSON(t, client, baseURL+"/password/forgot", body, http.StatusOK, "")
	res.Body.Close()

	res = postJSON(t, client, baseURL+"/password/forgot", body, http.StatusTooManyRequests, "")
	res.Body.Close()
}

func TestLockoutRedis(t *testing.T) {
	mr := mustStartMiniRedis(t)
	env := startTestEnv(t, map[string]string{
		"LOCKOUT_MAX_ATTEMPTS": "2",
		"LOCKOUT_WINDOW":       "2s",
		"LOCKOUT_BLOCK_FOR":    "2s",
		"LOCKOUT_REDIS_URL":    mr.Addr(),
	})
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "ivan@example.com", "ivan", "LockRedis1!")

	bad := `{"identifier":"ivan@example.com","password":"wrong"}`
	var res *http.Response
	for i := 0; i < 2; i++ {
		res = postJSON(t, client, baseURL+"/login", bad, http.StatusUnauthorized, "")
		res.Body.Close()
	}
	res = postJSON(t, client, baseURL+"/login", bad, http.StatusTooManyRequests, "")
	res.Body.Close()
	mr.FastForward(3 * time.Second)
	good := `{"identifier":"ivan@example.com","password":"LockRedis1!"}`
	res = postJSON(t, client, baseURL+"/login", good, http.StatusOK, "")
	res.Body.Close()
}

func TestAuditAndMetrics(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "audit@example.com", "audit", "AuditP@ss1")
	res := postJSON(t, client, baseURL+"/login", `{"identifier":"audit@example.com","password":"AuditP@ss1"}`, http.StatusOK, "")
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, baseURL+"/metrics", nil)
	res, err := client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("metrics status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	req, _ = http.NewRequest(http.MethodGet, baseURL+"/healthz", nil)
	res, err = client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("healthz status=%d err=%v", status(res), err)
	}
	res.Body.Close()

	var count int
	row := env.db.QueryRow("SELECT COUNT(*) FROM audit_log")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("audit count: %v", err)
	}
	if count == 0 {
		t.Fatalf("expected audit events recorded")
	}
}

func TestCitextMigrationExists(t *testing.T) {
	env := startTestEnv(t, nil)
	var exists bool
	err := env.db.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname='citext')").Scan(&exists)
	if err != nil {
		t.Fatalf("citext check: %v", err)
	}
	if !exists {
		t.Fatalf("citext extension missing")
	}
}

func TestSameSiteNoneCSRF(t *testing.T) {
	env := startTestEnv(t, map[string]string{
		"COOKIE_SAMESITE": "None",
		"COOKIE_SECURE":   "false",
	})
	baseURL := env.baseURL
	client := env.client

	registerAndVerify(t, env, "samesite@example.com", "samesite", "SiteP@ss1")

	loginBody := `{"identifier":"samesite@example.com","password":"SiteP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	cookies := res.Cookies()
	foundNone := false
	for _, c := range cookies {
		if c.Name == "csrf_token" && strings.Contains(c.String(), "SameSite=None") {
			foundNone = true
		}
	}
	if !foundNone {
		t.Fatalf("csrf cookie missing SameSite=None")
	}
	res.Body.Close()

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/logout", nil)
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("logout without csrf failed: %v", err)
	}
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 without csrf, got %d", res.StatusCode)
	}
	res.Body.Close()
}

func TestOAuthPendingMFALoginCompleteFlow(t *testing.T) {
	env := startTestEnv(t, nil)
	ctx := context.Background()

	user, err := env.svc.Register(ctx, "oauth-mfa@example.com", "oauthmfa", "OAuthP@ss1", "127.0.0.1", "integration-test")
	if err != nil {
		t.Fatalf("register oauth mfa user: %v", err)
	}
	token, err := env.svc.StartEmailVerification(ctx, user.Email, "127.0.0.1", "integration-test")
	if err != nil || token == "" {
		t.Fatalf("start email verification: %v", err)
	}
	if err := env.svc.CompleteEmailVerification(ctx, token, "127.0.0.1", "integration-test"); err != nil {
		t.Fatalf("complete email verification: %v", err)
	}
	secret, _, err := env.svc.SetupTOTP(ctx, user.ID, user.Email, "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	loginByPassword, err := env.svc.Login(ctx, user.Email, "OAuthP@ss1", "", "", "127.0.0.1", "integration-test", auth.DeviceBinding{ClientFamily: "browser"})
	if err != nil {
		t.Fatalf("login for totp enrollment: %v", err)
	}
	if _, _, err := env.svc.ConfirmTOTPAndReissue(ctx, user.ID, code, security.HashToken(loginByPassword.SessionToken)); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	if err := env.svc.LinkIdentity(ctx, user.ID, "spotify", "spotify-subject", user.Email, true); err != nil {
		t.Fatalf("link identity: %v", err)
	}
	login, err := env.svc.LoginWithOAuth(ctx, "spotify", "spotify-subject", user.Email, true, "127.0.0.1", "integration-test", auth.DeviceBinding{ClientFamily: "browser"})
	if err != nil {
		t.Fatalf("oauth login: %v", err)
	}
	if !login.RequiresMFA || login.PendingState == "" {
		t.Fatalf("expected pending oauth mfa state, got %+v", login)
	}
	setJarCookie(t, env.client.Jar, env.baseURL+"/oauth/login/complete", &http.Cookie{
		Name:  "oauth_login_pending",
		Value: login.PendingState,
		Path:  "/oauth",
	})
	code, err = security.TOTPCode(secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("generate totp for completion: %v", err)
	}
	res := postJSON(t, env.client, env.baseURL+"/oauth/login/complete", fmt.Sprintf(`{"totp_code":"%s"}`, code), http.StatusOK, "")
	res.Body.Close()

	sessionToken := readCookie(env.client.Jar, env.baseURL, env.cfg.Cookie.Name)
	if sessionToken == "" {
		t.Fatalf("session cookie missing after oauth login complete")
	}
	_, sess, err := env.svc.ValidateSession(ctx, sessionToken, validationFromClient(env.client, env))
	if err != nil {
		t.Fatalf("validate session after oauth login complete: %v", err)
	}
	if sess.AAL != 2 {
		t.Fatalf("expected aal=2 after oauth login complete, got %d", sess.AAL)
	}

	req, _ := http.NewRequest(http.MethodGet, env.baseURL+"/me", nil)
	res, err = env.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("me after oauth login complete status=%d err=%v", status(res), err)
	}
	res.Body.Close()
}

func TestOAuthOnlyAccountCanBootstrapMFAWithFreshSession(t *testing.T) {
	env := startTestEnv(t, nil)
	ctx := context.Background()

	login, err := env.svc.LoginWithOAuth(ctx, "google", "passwordless-subject", "passwordless@example.com", true, "127.0.0.1", "integration-test", auth.DeviceBinding{ClientFamily: "browser"})
	if err != nil {
		t.Fatalf("create oauth-only account: %v", err)
	}
	if login.RequiresMFA {
		t.Fatalf("unexpected pending mfa for fresh oauth-only account")
	}
	setJarCookie(t, env.client.Jar, env.baseURL, &http.Cookie{
		Name:  env.cfg.Cookie.Name,
		Value: login.SessionToken,
		Path:  "/",
	})
	setJarCookie(t, env.client.Jar, env.baseURL, &http.Cookie{
		Name:  env.cfg.Cookie.DeviceName,
		Value: login.DeviceToken,
		Path:  "/",
	})
	setJarCookie(t, env.client.Jar, env.baseURL, &http.Cookie{
		Name:  "csrf_token",
		Value: login.CSRFToken,
		Path:  "/",
	})

	req, _ := http.NewRequest(http.MethodPost, env.baseURL+"/mfa/totp/setup", nil)
	req.Header.Set("X-CSRF-Token", login.CSRFToken)
	res, err := env.client.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("passwordless totp setup status=%d err=%v", status(res), err)
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)
	if setupResp.Secret == "" {
		t.Fatalf("missing totp secret for passwordless account")
	}

	code, err := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("generate passwordless totp: %v", err)
	}
	res = postJSON(t, env.client, env.baseURL+"/mfa/totp/verify", fmt.Sprintf(`{"code":"%s"}`, code), http.StatusOK, login.CSRFToken)
	res.Body.Close()

	newSessionToken := readCookie(env.client.Jar, env.baseURL, env.cfg.Cookie.Name)
	if newSessionToken == "" || newSessionToken == login.SessionToken {
		t.Fatalf("expected rotated session after enabling mfa on passwordless account")
	}
	if _, _, err := env.svc.ValidateSession(ctx, login.SessionToken, validationFromClient(env.client, env)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expected old session token to be invalid after mfa enable, got %v", err)
	}
	_, sess, err := env.svc.ValidateSession(ctx, newSessionToken, validationFromClient(env.client, env))
	if err != nil {
		t.Fatalf("validate rotated session: %v", err)
	}
	if sess.AAL != 2 {
		t.Fatalf("expected aal=2 after passwordless mfa enable, got %d", sess.AAL)
	}
}

func TestSensitiveReauthRotatesSessionAndRejectsOldToken(t *testing.T) {
	env := startTestEnv(t, map[string]string{"MFA_STEPUP_MAX_AGE": "100ms"})
	baseURL := env.baseURL
	client := env.client
	ctx := context.Background()

	registerAndVerify(t, env, "reauth@example.com", "reauth", "StepUpP@ss1")

	loginBody := `{"identifier":"reauth@example.com","password":"StepUpP@ss1"}`
	res := postJSON(t, client, baseURL+"/login", loginBody, http.StatusOK, "")
	csrf := readCookie(client.Jar, baseURL, "csrf_token")
	oldToken := readCookie(client.Jar, baseURL, env.cfg.Cookie.Name)
	res.Body.Close()
	if oldToken == "" || csrf == "" {
		t.Fatalf("missing initial session or csrf")
	}
	_, oldSession, err := env.svc.ValidateSession(ctx, oldToken, validationFromClient(client, env))
	if err != nil {
		t.Fatalf("validate initial session: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	res = postJSON(t, client, baseURL+"/mfa/totp/setup", `{"current_password":"StepUpP@ss1"}`, http.StatusOK, csrf)
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)
	if setupResp.Secret == "" {
		t.Fatalf("missing secret after reauth setup")
	}

	newToken := readCookie(client.Jar, baseURL, env.cfg.Cookie.Name)
	if newToken == "" || newToken == oldToken {
		t.Fatalf("expected sensitive reauth to rotate session")
	}
	if _, _, err := env.svc.ValidateSession(ctx, oldToken, validationFromClient(client, env)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expected old token invalid after sensitive reauth, got %v", err)
	}
	_, newSession, err := env.svc.ValidateSession(ctx, newToken, validationFromClient(client, env))
	if err != nil {
		t.Fatalf("validate rotated reauth session: %v", err)
	}
	if newSession.AAL != 1 {
		t.Fatalf("expected aal=1 after password reauth, got %d", newSession.AAL)
	}
	if !newSession.AuthTime.After(oldSession.AuthTime) {
		t.Fatalf("expected auth_time refresh after sensitive reauth")
	}
}

func TestMFAEnableRevokesSiblingSessionsAndPromotesAAL(t *testing.T) {
	env := startTestEnv(t, nil)
	baseURL := env.baseURL
	ctx := context.Background()
	clientA := env.client
	clientB := newCookieClient()

	registerAndVerify(t, env, "sibling@example.com", "sibling", "SiblingP@ss1")

	loginBody := `{"identifier":"sibling@example.com","password":"SiblingP@ss1"}`
	res := postJSON(t, clientA, baseURL+"/login", loginBody, http.StatusOK, "")
	csrfA := readCookie(clientA.Jar, baseURL, "csrf_token")
	tokenA := readCookie(clientA.Jar, baseURL, env.cfg.Cookie.Name)
	res.Body.Close()
	if csrfA == "" || tokenA == "" {
		t.Fatalf("missing clientA session")
	}

	res = postJSON(t, clientB, baseURL+"/login", loginBody, http.StatusOK, "")
	tokenB := readCookie(clientB.Jar, baseURL, env.cfg.Cookie.Name)
	res.Body.Close()
	if tokenB == "" {
		t.Fatalf("missing clientB session")
	}

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/mfa/totp/setup", nil)
	req.Header.Set("X-CSRF-Token", csrfA)
	res, err := clientA.Do(req)
	if err != nil || res.StatusCode != http.StatusOK {
		t.Fatalf("clientA totp setup status=%d err=%v", status(res), err)
	}
	var setupResp struct {
		Secret string `json:"secret"`
	}
	decodeBody(t, res, &setupResp)
	if setupResp.Secret == "" {
		t.Fatalf("missing sibling totp secret")
	}

	code, err := security.TOTPCode(setupResp.Secret, time.Now(), 6, 30)
	if err != nil {
		t.Fatalf("generate sibling totp: %v", err)
	}
	res = postJSON(t, clientA, baseURL+"/mfa/totp/verify", fmt.Sprintf(`{"code":"%s"}`, code), http.StatusOK, csrfA)
	res.Body.Close()

	newTokenA := readCookie(clientA.Jar, baseURL, env.cfg.Cookie.Name)
	if newTokenA == "" || newTokenA == tokenA {
		t.Fatalf("expected clientA session rotation after mfa enable")
	}
	if _, _, err := env.svc.ValidateSession(ctx, tokenB, validationFromClient(clientB, env)); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expected sibling session to be revoked, got %v", err)
	}
	req, _ = http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	res, err = clientB.Do(req)
	if err != nil {
		t.Fatalf("clientB me after revoke: %v", err)
	}
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected clientB unauthorized after sibling revoke, got %d", res.StatusCode)
	}
	res.Body.Close()
	_, sess, err := env.svc.ValidateSession(ctx, newTokenA, validationFromClient(clientA, env))
	if err != nil {
		t.Fatalf("validate clientA rotated session: %v", err)
	}
	if sess.AAL != 2 {
		t.Fatalf("expected clientA aal=2 after mfa enable, got %d", sess.AAL)
	}
}

func readCookie(jar http.CookieJar, baseURL, name string) string {
	u, _ := url.Parse(baseURL)
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func createTempDB(t *testing.T, dsn string) (string, string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	base := *parsed
	base.Path = "/postgres"
	adminDSN := base.String()
	name := fmt.Sprintf("test_auth_%d", time.Now().UnixNano())

	adminDB, err := sql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	defer adminDB.Close()

	if _, err := adminDB.Exec(fmt.Sprintf("CREATE DATABASE %s", pqQuoteIdentifier(name))); err != nil {
		t.Fatalf("create db: %v", err)
	}
	parsed.Path = "/" + name
	return name, parsed.String()
}

func dropDB(t *testing.T, dsn, name string) {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return
	}
	parsed.Path = "/postgres"
	adminDSN := parsed.String()
	db, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return
	}
	defer db.Close()
	_, _ = db.Exec(fmt.Sprintf("DROP DATABASE IF EXISTS %s", pqQuoteIdentifier(name)))
}

func runMigrations(t *testing.T, dsn string) {
	t.Helper()
	files, err := os.ReadDir("db/migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".sql") {
			continue
		}
		sqlBytes, err := os.ReadFile(path.Join("db/migrations", f.Name()))
		if err != nil {
			t.Fatalf("read migration %s: %v", f.Name(), err)
		}
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("exec migration %s: %v", f.Name(), err)
		}
	}
}

func pqQuoteIdentifier(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

type testEnv struct {
	baseURL string
	client  *http.Client
	svc     *auth.Service
	db      *sql.DB
	dsn     string
	cfg     config.Config
}

func startTestEnv(t *testing.T, envVars map[string]string) *testEnv {
	baseDSN := os.Getenv("DATABASE_URL")
	if baseDSN == "" {
		t.Skip("DATABASE_URL not set; skipping integration test")
	}
	enc := os.Getenv("ENCRYPTION_KEY")
	if enc == "" {
		t.Skip("ENCRYPTION_KEY not set; skipping integration test")
	}
	for k, v := range envVars {
		t.Setenv(k, v)
	}

	testDBName, dbDSN := createTempDB(t, baseDSN)
	t.Cleanup(func() { dropDB(t, baseDSN, testDBName) })

	t.Setenv("DATABASE_URL", dbDSN)
	t.Setenv("ENCRYPTION_KEY", enc)
	if os.Getenv("AUTH_INTERNAL_TOKEN") == "" {
		t.Setenv("AUTH_INTERNAL_TOKEN", "integration-internal-token")
	}
	if os.Getenv("AUTH_EMAIL_VERIFICATION_INTERNAL_TOKEN") == "" {
		t.Setenv("AUTH_EMAIL_VERIFICATION_INTERNAL_TOKEN", "integration-email-token")
	}
	if os.Getenv("AUTH_ENABLE_INTERNAL_EMAIL_ISSUE") == "" {
		t.Setenv("AUTH_ENABLE_INTERNAL_EMAIL_ISSUE", "true")
	}
	if os.Getenv("EMAIL_OUTBOX_DIR") == "" {
		t.Setenv("EMAIL_OUTBOX_DIR", t.TempDir())
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	runMigrations(t, dbDSN)

	db, err := sql.Open("pgx", dbDSN)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := postgres.New(db)
	svc := auth.New(store, cfg)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	server := handlers.NewServer(cfg, logger, svc)

	srv := &http.Server{Handler: server}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
		_ = ln.Close()
	})
	baseURL := fmt.Sprintf("http://%s", ln.Addr().String())

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 10 * time.Second}

	return &testEnv{
		baseURL: baseURL,
		client:  client,
		svc:     svc,
		db:      db,
		dsn:     dbDSN,
		cfg:     cfg,
	}
}

func newCookieClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func setJarCookie(t *testing.T, jar http.CookieJar, rawURL string, cookie *http.Cookie) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse cookie url %q: %v", rawURL, err)
	}
	jar.SetCookies(u, []*http.Cookie{cookie})
}

func postJSON(t *testing.T, client *http.Client, url string, body string, expectedStatus int, csrf string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Client-Family", "cli")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s failed: %v", url, err)
	}
	if res.StatusCode != expectedStatus {
		t.Fatalf("expected status %d, got %d", expectedStatus, res.StatusCode)
	}
	return res
}

func issueEmailVerificationToken(t *testing.T, env *testEnv, email string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, env.baseURL+"/internal/email-verifications/issue", bytes.NewBufferString(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", env.cfg.Security.EmailIssueToken)
	res, err := env.client.Do(req)
	if err != nil {
		t.Fatalf("issue email verification token: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("issue email verification token status=%d", res.StatusCode)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode email verification token: %v", err)
	}
	if payload.Token == "" {
		t.Fatal("email verification token missing")
	}
	return payload.Token
}

func verifyEmail(t *testing.T, env *testEnv, email string) {
	t.Helper()
	token := issueEmailVerificationToken(t, env, email)
	body := `{"token":"` + token + `"}`
	res := postJSON(t, env.client, env.baseURL+"/email/verify/confirm", body, http.StatusOK, "")
	res.Body.Close()
}

func waitForOutboxToken(t *testing.T, dir, prefix, email string) string {
	t.Helper()
	want := sanitizeOutboxRecipient(email)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for i := len(entries) - 1; i >= 0; i-- {
				name := entries[i].Name()
				if entries[i].IsDir() || !strings.HasPrefix(name, prefix) || !strings.Contains(name, want) {
					continue
				}
				payload, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil {
					continue
				}
				token := extractLastTokenLine(string(payload))
				if token != "" {
					return token
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("token with prefix %s for %s not found in outbox %s", prefix, email, dir)
	return ""
}

func sanitizeOutboxRecipient(email string) string {
	email = strings.TrimSpace(strings.ToLower(email))
	replacer := strings.NewReplacer("@", "_at_", "/", "_", "\\", "_", ":", "_", " ", "_")
	return replacer.Replace(email)
}

func extractLastTokenLine(payload string) string {
	lines := strings.Split(payload, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "submit it to post ") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "use this ") {
			continue
		}
		return line
	}
	return ""
}

func registerAndVerify(t *testing.T, env *testEnv, email, username, password string) {
	t.Helper()
	body := fmt.Sprintf(`{"email":"%s","username":"%s","password":"%s"}`, email, username, password)
	res := postJSON(t, env.client, env.baseURL+"/register", body, http.StatusCreated, "")
	res.Body.Close()
	verifyEmail(t, env, email)
}

func validationFromClient(client *http.Client, env *testEnv) auth.SessionValidation {
	return auth.SessionValidation{
		DeviceToken:     readCookie(client.Jar, env.baseURL, env.cfg.Cookie.DeviceName),
		ClientFamily:    "cli",
		IP:              "127.0.0.1",
		UserAgent:       "integration-test",
		RefreshMetadata: true,
	}
}

func decodeBody(t *testing.T, res *http.Response, out any) {
	t.Helper()
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
}

func status(res *http.Response) int {
	if res == nil {
		return 0
	}
	return res.StatusCode
}

func mustStartMiniRedis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr
}
