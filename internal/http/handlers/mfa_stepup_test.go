package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

func TestBackupRegenerateRequiresStepUpWhenMFAEnabled(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/backup/regenerate", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-1"})
	req.Header.Set("X-CSRF-Token", "csrf-1")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing step-up, got %d", rr.Code)
	}
}

func TestBackupRegenerateAllowsAAL2Session(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 2, time.Now().Add(-time.Minute))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/backup/regenerate", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-2"})
	req.Header.Set("X-CSRF-Token", "csrf-2")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with step-up session, got %d", rr.Code)
	}
}

func TestBackupRegenerateRequiresFreshAAL2Session(t *testing.T) {
	cfg := baseConfig()
	cfg.Security.MFAStepUpMaxAge = 5 * time.Minute
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 2, time.Now().Add(-10*time.Minute))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/backup/regenerate", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-3"})
	req.Header.Set("X-CSRF-Token", "csrf-3")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for stale AAL2 session, got %d", rr.Code)
	}
}

func TestBackupRegenerateRequiresReauthWhenDeviceRiskChanges(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 2, time.Now().Add(-time.Minute))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/backup/regenerate", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-risk"})
	req.Header.Set("X-CSRF-Token", "csrf-risk")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when device risk changed, got %d", rr.Code)
	}
}

func TestTOTPSetupRequiresCurrentPasswordWhenMFADisabled(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "u@example.com",
		Username:            "u",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/setup", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-setup"})
	req.Header.Set("X-CSRF-Token", "csrf-setup")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without current password, got %d", rr.Code)
	}

	body, _ := json.Marshal(map[string]string{"current_password": password})
	req = httptest.NewRequest(http.MethodPost, "/mfa/totp/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-setup-2"})
	req.Header.Set("X-CSRF-Token", "csrf-setup-2")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with current password, got %d", rr.Code)
	}
}

func TestTOTPSetupAllowsPasswordlessFreshSession(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "u@example.com",
		Username:            "u",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          false,
	}
	rawToken, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/setup", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-passwordless-setup"})
	req.Header.Set("X-CSRF-Token", "csrf-passwordless-setup")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for passwordless fresh session, got %d", rr.Code)
	}
}

func TestTOTPVerifyRequiresCurrentPasswordWhenMFADisabled(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	password := "StrongPass1!"
	rawToken, hash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "u@example.com",
		Username:            "u",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
	}
	srv := newTestServer(fs, cfg)

	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "u@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"code": code})
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-verify"})
	req.Header.Set("X-CSRF-Token", "csrf-verify")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without current password, got %d", rr.Code)
	}

	body, _ = json.Marshal(map[string]string{"code": code, "current_password": password})
	req = httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-verify-2"})
	req.Header.Set("X-CSRF-Token", "csrf-verify-2")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with current password, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected old session token hash to be rotated away after password reauth")
	}
	newSession := findOnlySessionForUser(t, fs, 10)
	if !newSession.AuthTime.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("expected auth_time refresh after password reauth, got %s", newSession.AuthTime)
	}
	if newSession.AAL != 2 {
		t.Fatalf("expected enabling MFA to reissue the session at AAL2, got %d", newSession.AAL)
	}
}

func TestBackupRegenerateAllowsBodyMFACodeAndRefreshesAuthTime(t *testing.T) {
	cfg := baseConfig()
	cfg.Security.MFAStepUpMaxAge = 5 * time.Minute
	fs := newFakeStore()

	_, hash := newSessionForTest(t, fs, 10, 2, time.Now().Add(-10*time.Minute))
	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	srv := newTestServer(fs, cfg)

	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "u@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	_, rotation, err := srv.auth.ConfirmTOTPAndReissue(context.Background(), 10, code, hash)
	if err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	rawToken := rotation.SessionToken
	hash = security.HashToken(rawToken)
	session := findSessionByToken(t, fs, rawToken)
	session.AuthTime = time.Now().Add(-10 * time.Minute)

	body, _ := json.Marshal(map[string]string{"reauth_totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/mfa/backup/regenerate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-body-stepup"})
	req.Header.Set("X-CSRF-Token", "csrf-body-stepup")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with body reauth totp code, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected old session token hash to be rotated away after MFA reauth")
	}
	newSession := findOnlySessionForUser(t, fs, 10)
	if !newSession.AuthTime.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("expected auth_time refresh after MFA reauth, got %s", newSession.AuthTime)
	}
}

func TestTOTPSetupKeepsExistingActiveSecretUntilPendingVerification(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "u@example.com",
		Username:            "u",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
	}

	secret1, _, err := srv.auth.SetupTOTP(context.Background(), 10, "u@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup initial totp: %v", err)
	}
	code1, err := security.TOTPCode(secret1, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("code1: %v", err)
	}
	_, initialHash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	if _, _, err := srv.auth.ConfirmTOTPAndReissue(context.Background(), 10, code1, initialHash); err != nil {
		t.Fatalf("confirm initial totp: %v", err)
	}
	_ = fs.DeleteSessionsByUserID(context.Background(), 10)

	secret2, _, err := srv.auth.SetupTOTP(context.Background(), 10, "u@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup pending totp: %v", err)
	}
	record, err := fs.GetTOTP(context.Background(), 10)
	if err != nil || record == nil {
		t.Fatalf("expected totp record, got err=%v", err)
	}
	if len(record.PendingEncryptedSecret) == 0 || len(record.PendingNonce) == 0 {
		t.Fatalf("expected pending totp secret to be staged")
	}
	if okErr := srv.auth.VerifyMFAChallenge(context.Background(), 10, code1, ""); okErr != nil {
		t.Fatalf("expected old totp secret to remain active until confirmation, got %v", okErr)
	}

	code2, err := security.TOTPCode(secret2, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("code2: %v", err)
	}
	_, pendingHash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	if _, _, err := srv.auth.ConfirmTOTPAndReissue(context.Background(), 10, code2, pendingHash); err != nil {
		t.Fatalf("confirm pending totp: %v", err)
	}
	_ = fs.DeleteSessionsByUserID(context.Background(), 10)
	record, err = fs.GetTOTP(context.Background(), 10)
	if err != nil || record == nil {
		t.Fatalf("expected totp record after promote, got err=%v", err)
	}
	if len(record.PendingEncryptedSecret) != 0 || len(record.PendingNonce) != 0 {
		t.Fatalf("expected pending totp secret to be cleared after confirmation")
	}
	if err := srv.auth.VerifyMFAChallenge(context.Background(), 10, code1, ""); err == nil {
		t.Fatalf("expected old totp secret to stop working after promotion")
	}
	if err := srv.auth.VerifyMFAChallenge(context.Background(), 10, code2, ""); err != nil {
		t.Fatalf("expected new totp secret to work after promotion, got %v", err)
	}
}

func TestTOTPVerifyReissuesCurrentSessionAndRevokesOtherSessions(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "u@example.com",
		Username:            "u",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
	}
	rawToken, hash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	_, otherHash := newSessionForTest(t, fs, 10, 2, time.Now().Add(-time.Minute))
	srv := newTestServer(fs, cfg)

	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "u@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"code": code, "current_password": password})
	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-verify-rotate"})
	req.Header.Set("X-CSRF-Token", "csrf-verify-rotate")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 enabling MFA, got %d", rr.Code)
	}
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected current session hash to be rotated after MFA enable")
	}
	if _, ok := fs.sessions[otherHash]; ok {
		t.Fatalf("expected secondary sessions to be revoked after MFA enable")
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	newSession := findOnlySessionForUser(t, fs, 10)
	if newSession.AAL != 2 {
		t.Fatalf("expected rotated session to become AAL2, got %d", newSession.AAL)
	}
}

func TestTOTPDisableReissuesCurrentSessionAndRevokesOtherSessions(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()

	fs.users[10] = &store.User{
		ID:         10,
		TenantID:   "tenant-1",
		Email:      "u@example.com",
		Username:   "u",
		Status:     "active",
		MFAEnabled: true,
	}
	now := time.Now()
	rawToken, hash := newSessionForTest(t, fs, 10, 2, now.Add(-time.Minute))
	_, otherHash := newSessionForTest(t, fs, 10, 2, now.Add(-time.Minute))
	enabledAt := now.Add(-time.Hour)
	fs.totp[10] = &store.MFATOTP{
		UserID:          10,
		EncryptedSecret: []byte("secret"),
		Nonce:           []byte("nonce"),
		EnabledAt:       &enabledAt,
	}
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/mfa/totp/disable", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-disable-rotate"})
	req.Header.Set("X-CSRF-Token", "csrf-disable-rotate")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 disabling MFA, got %d", rr.Code)
	}
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected current session hash to be rotated after MFA disable")
	}
	if _, ok := fs.sessions[otherHash]; ok {
		t.Fatalf("expected secondary sessions to be revoked after MFA disable")
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	newSession := findOnlySessionForUser(t, fs, 10)
	if newSession.AAL != 1 {
		t.Fatalf("expected rotated session to drop to AAL1, got %d", newSession.AAL)
	}
}
