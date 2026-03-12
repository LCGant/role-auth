package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/LCGant/role-auth/internal/oauth/providers"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
	"golang.org/x/oauth2"
)

func ptrInt64(v int64) *int64 {
	return &v
}

func TestOAuthStartSetsStateCookie(t *testing.T) {
	cfg := baseConfig()
	cfg.HTTP.PublicURL = "https://gateway.example/auth"
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)
	srv.google = &providers.GoogleProvider{
		Config: &oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "http://localhost:8080/oauth/google/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.example/authorize",
				TokenURL: "https://accounts.example/token",
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/start", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatalf("expected redirect location")
	}
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("expected state in redirect URL")
	}

	result := rr.Result()
	defer result.Body.Close()
	foundStateCookie := false
	for _, c := range result.Cookies() {
		if c.Name == "oauth_state" && c.Value == state {
			if c.Path != "/auth/oauth" {
				t.Fatalf("expected oauth_state path /auth/oauth, got %q", c.Path)
			}
			foundStateCookie = true
			break
		}
	}
	if !foundStateCookie {
		t.Fatalf("expected oauth_state cookie with generated state")
	}
	if _, ok := fs.oauthStates[state]; !ok {
		t.Fatalf("expected oauth state to be persisted")
	}
}

func TestOAuthCallbackRejectsMissingStateCookie(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	fs.oauthStates["state-1"] = store.OAuthState{
		State:        "state-1",
		Provider:     "google",
		Action:       "login",
		CodeVerifier: "verifier-1",
		Nonce:        "nonce-1",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state-1&code=abc", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestOAuthCallbackReturnsNotFoundWhenProviderDisabled(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	fs.oauthStates["state-2"] = store.OAuthState{
		State:        "state-2",
		Provider:     "google",
		Action:       "login",
		CodeVerifier: "verifier-2",
		Nonce:        "nonce-2",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback?state=state-2&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: "oauth_state", Value: "state-2"})
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when provider is not configured, got %d", rr.Code)
	}
}

func TestOAuthLinkCallbackUsesPriorStepUpWithoutHeaderChallenge(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	userID := int64(99)
	user := &store.User{
		ID:         userID,
		TenantID:   "tenant-1",
		Email:      "user@example.com",
		Username:   "user",
		Status:     "active",
		MFAEnabled: true,
	}
	session := &store.Session{
		ID:        1,
		UserID:    userID,
		AAL:       2,
		CreatedAt: time.Now(),
	}
	state := &store.OAuthState{
		State:    "state-link",
		Provider: "google",
		Action:   "link",
		UserID:   &userID,
	}

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback", nil)
	ctx := context.WithValue(req.Context(), ctxUserKey, user)
	ctx = context.WithValue(ctx, ctxSessionKey, session)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	srv.handleOAuthResult(rr, req, state, "google", "sub-1", "user@example.com", true)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for link callback using prior step-up, got %d", rr.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["linked"] != "google" {
		t.Fatalf("expected linked=google, got %+v", body)
	}
}

func TestOAuthLinkStartRequiresCurrentPasswordWhenMFADisabled(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)
	srv.google = &providers.GoogleProvider{
		Config: &oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "http://localhost:8080/oauth/google/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.example/authorize",
				TokenURL: "https://accounts.example/token",
			},
		},
	}

	password := "StrongPass1!"
	rawToken, hash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
		EmailVerified:       true,
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/google/link", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-link-1"})
	req.Header.Set("X-CSRF-Token", "csrf-link-1")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without current password, got %d", rr.Code)
	}

	body, _ := json.Marshal(map[string]string{"current_password": password})
	req = httptest.NewRequest(http.MethodPost, "/oauth/google/link", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-link-2"})
	req.Header.Set("X-CSRF-Token", "csrf-link-2")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 with current password, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected oauth link reauth to rotate the old session")
	}
	newSession := findOnlySessionForUser(t, fs, 10)
	if !newSession.AuthTime.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("expected auth_time to refresh after password reauth, got %s", newSession.AuthTime)
	}
	if newSession.AAL != 1 {
		t.Fatalf("expected password reauth not to inflate AAL, got %d", newSession.AAL)
	}
}

func TestOAuthLinkStartAllowsPasswordlessFreshSession(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)
	srv.google = &providers.GoogleProvider{
		Config: &oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "http://localhost:8080/oauth/google/callback",
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.example/authorize",
				TokenURL: "https://accounts.example/token",
			},
		},
	}

	rawToken, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          false,
		EmailVerified:       true,
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/google/link", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-link-passwordless"})
	req.Header.Set("X-CSRF-Token", "csrf-link-passwordless")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 for passwordless fresh session, got %d", rr.Code)
	}
}

func TestOAuthResultRejectsProvisioningWithoutVerifiedEmail(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback", nil)
	rr := httptest.NewRecorder()
	srv.handleOAuthResult(rr, req, &store.OAuthState{Action: "login"}, "spotify", "sub-1", "", false)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when oauth provisioning lacks verified email, got %d", rr.Code)
	}
}

func TestOAuthResultRequiresMFAForExistingOAuthUser(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          true,
	}
	_ = fs.CreateIdentity(context.Background(), &store.Identity{UserID: 10, Provider: "google", Subject: "sub-google"})

	req := httptest.NewRequest(http.MethodGet, "/oauth/google/callback", nil)
	rr := httptest.NewRecorder()
	srv.handleOAuthResult(rr, req, &store.OAuthState{Action: "login"}, "google", "sub-google", "user@example.com", true)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with mfa_required, got %d", rr.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["mfa_required"] != true {
		t.Fatalf("expected mfa_required response, got %+v", body)
	}
	pending := findCookieValue(t, rr, "oauth_login_pending")
	state, err := fs.GetOAuthState(context.Background(), pending)
	if err != nil || state == nil {
		t.Fatalf("expected pending oauth login state, got err=%v", err)
	}
	if state.Action != "login_mfa" || state.UserID == nil || *state.UserID != 10 {
		t.Fatalf("unexpected pending state: %+v", state)
	}
}

func TestOAuthLoginCompleteIssuesAAL2Session(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          true,
	}
	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "user@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	_, tokenHash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	if _, _, err := srv.auth.ConfirmTOTPAndReissue(context.Background(), 10, code, tokenHash); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	_ = fs.DeleteSessionsByUserID(context.Background(), 10)
	fs.oauthStates["pending-login"] = store.OAuthState{
		State:     "pending-login",
		Provider:  "google",
		Action:    "login_mfa",
		UserID:    ptrInt64(10),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	body, _ := json.Marshal(map[string]string{"totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/oauth/login/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "oauth_login_pending", Value: "pending-login"})
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 completing oauth mfa login, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	session := findOnlySessionForUser(t, fs, 10)
	if session.AAL != 2 {
		t.Fatalf("expected oauth mfa completion to issue AAL2 session, got %d", session.AAL)
	}
	state, err := fs.GetOAuthState(context.Background(), "pending-login")
	if err != nil {
		t.Fatalf("get pending state: %v", err)
	}
	if state != nil {
		t.Fatalf("expected pending state to be consumed on successful completion")
	}
}

func TestOAuthLoginCompleteConsumesPendingStateAtomically(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          true,
	}
	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "user@example.com", "role-auth")
	if err != nil {
		t.Fatalf("setup totp: %v", err)
	}
	code, err := security.TOTPCode(secret, time.Now(), security.DefaultTOTPDigits, security.DefaultTOTPPeriod)
	if err != nil {
		t.Fatalf("totp code: %v", err)
	}
	_, tokenHash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	if _, _, err := srv.auth.ConfirmTOTPAndReissue(context.Background(), 10, code, tokenHash); err != nil {
		t.Fatalf("confirm totp: %v", err)
	}
	_ = fs.DeleteSessionsByUserID(context.Background(), 10)
	fs.oauthStates["pending-login"] = store.OAuthState{
		State:     "pending-login",
		Provider:  "google",
		Action:    "login_mfa",
		UserID:    ptrInt64(10),
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	body, _ := json.Marshal(map[string]string{"totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/oauth/login/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "oauth_login_pending", Value: "pending-login"})
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected first completion to succeed, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/oauth/login/complete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "oauth_login_pending", Value: "pending-login"})
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected replayed completion to fail once state is consumed, got %d", rr.Code)
	}
}

func TestOAuthUnlinkRequiresReauthAndAllowsLastIdentityWhenPasswordLoginExists(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	password := "StrongPass1!"
	rawToken, hash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
		MFAEnabled:          false,
		EmailVerified:       true,
	}
	_ = fs.CreateIdentity(context.Background(), &store.Identity{UserID: 10, Provider: "google", Subject: "sub-google"})

	req := httptest.NewRequest(http.MethodPost, "/oauth/google/unlink", nil)
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-unlink"})
	req.Header.Set("X-CSRF-Token", "csrf-unlink")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without reauth, got %d", rr.Code)
	}

	body, _ := json.Marshal(map[string]string{"current_password": password})
	req = httptest.NewRequest(http.MethodPost, "/oauth/google/unlink", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-unlink-2"})
	req.Header.Set("X-CSRF-Token", "csrf-unlink-2")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 when local password remains available, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	if _, ok := fs.sessions[hash]; ok {
		t.Fatalf("expected oauth unlink reauth to rotate the old session")
	}
}

func TestOAuthUnlinkProtectsLastIdentityForPasswordlessAccounts(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	_, hash := newSessionForTest(t, fs, 10, 2, time.Now().Add(-time.Minute))
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        "",
		PasswordAuthEnabled: false,
		Status:              "active",
		MFAEnabled:          true,
		EmailVerified:       true,
	}
	_ = fs.CreateIdentity(context.Background(), &store.Identity{UserID: 10, Provider: "google", Subject: "sub-google"})

	secret, _, err := srv.auth.SetupTOTP(context.Background(), 10, "user@example.com", "role-auth")
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

	body, _ := json.Marshal(map[string]string{"reauth_totp_code": code})
	req := httptest.NewRequest(http.MethodPost, "/oauth/google/unlink", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	addSessionCookies(t, req, cfg, fs, rawToken)
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-unlink-passwordless"})
	req.Header.Set("X-CSRF-Token", "csrf-unlink-passwordless")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when unlinking the last passwordless identity, got %d", rr.Code)
	}
}
