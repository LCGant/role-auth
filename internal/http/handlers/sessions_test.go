package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/LCGant/role-auth/internal/store"
)

func TestLoginSetsDeviceCookieAndReusesKnownDevice(t *testing.T) {
	cfg := baseConfig()
	cfg.HTTP.PublicURL = "https://auth.example"
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
	}

	body := []byte(`{"identifier":"user@example.com","password":"StrongPass1!"}`)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on first login, got %d", rr.Code)
	}
	deviceToken := findCookieValue(t, rr, cfg.Cookie.DeviceName)
	if len(fs.devices) != 1 {
		t.Fatalf("expected one tracked device after first login, got %d", len(fs.devices))
	}

	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://auth.example")
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.DeviceName, Value: deviceToken})
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 on second login, got %d", rr.Code)
	}
	if got := findCookieValue(t, rr, cfg.Cookie.DeviceName); got != deviceToken {
		t.Fatalf("expected device token to be reused, got %q", got)
	}
	if len(fs.devices) != 1 {
		t.Fatalf("expected known device reuse, got %d devices", len(fs.devices))
	}
}

func TestSessionRevokeRequiresReauthForOtherSessions(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
	}
	rawCurrent, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	_, _ = newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	other := newestNonCurrentSession(t, fs, 10)
	currentDeviceToken := deviceTokenForSession(t, fs, findSessionByToken(t, fs, rawCurrent))

	req := httptest.NewRequest(http.MethodPost, "/sessions/"+itoa(other.ID)+"/revoke", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: rawCurrent})
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.DeviceName, Value: currentDeviceToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-sessions"})
	req.Header.Set("X-CSRF-Token", "csrf-sessions")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without reauth, got %d", rr.Code)
	}

	body, _ := json.Marshal(map[string]string{"current_password": password})
	req = httptest.NewRequest(http.MethodPost, "/sessions/"+itoa(other.ID)+"/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: rawCurrent})
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.DeviceName, Value: currentDeviceToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-sessions-2"})
	req.Header.Set("X-CSRF-Token", "csrf-sessions-2")
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with reauth, got %d", rr.Code)
	}
	findCookieValue(t, rr, cfg.Cookie.Name)
	if countSessionsForUser(fs, 10) != 1 {
		t.Fatalf("expected only current rotated session to remain, got %d", countSessionsForUser(fs, 10))
	}
}

func TestDeviceRevokeClearsCurrentCookies(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)

	password := "StrongPass1!"
	fs.users[10] = &store.User{
		ID:                  10,
		TenantID:            "tenant-1",
		Email:               "user@example.com",
		Username:            "user",
		PasswordHash:        hashPasswordForTest(t, cfg, password),
		PasswordAuthEnabled: true,
		Status:              "active",
	}
	rawCurrent, currentHash := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	current := fs.sessions[currentHash]
	currentDeviceToken := deviceTokenForSession(t, fs, current)

	body, _ := json.Marshal(map[string]string{"current_password": password})
	req := httptest.NewRequest(http.MethodPost, "/devices/"+itoa(current.DeviceID)+"/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: rawCurrent})
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.DeviceName, Value: currentDeviceToken})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-device"})
	req.Header.Set("X-CSRF-Token", "csrf-device")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 revoking current device, got %d", rr.Code)
	}
	if !hasClearedCookie(rr, cfg.Cookie.Name) {
		t.Fatalf("expected current session cookie to be cleared")
	}
	if !hasClearedCookie(rr, cfg.Cookie.DeviceName) {
		t.Fatalf("expected current device cookie to be cleared")
	}
	if countSessionsForUser(fs, 10) != 0 {
		t.Fatalf("expected all sessions on current device to be removed")
	}
	if fs.devices[current.DeviceID].RevokedAt == nil {
		t.Fatalf("expected current device to be revoked")
	}
}

func newestNonCurrentSession(t *testing.T, fs *fakeStore, userID int64) *store.Session {
	t.Helper()
	var selected *store.Session
	for _, sess := range fs.sessions {
		if sess.UserID != userID {
			continue
		}
		if selected == nil || sess.ID > selected.ID {
			selected = sess
		}
	}
	if selected == nil {
		t.Fatalf("expected session for user %d", userID)
	}
	return selected
}

func countSessionsForUser(fs *fakeStore, userID int64) int {
	count := 0
	for _, sess := range fs.sessions {
		if sess.UserID == userID {
			count++
		}
	}
	return count
}

func hasClearedCookie(rr *httptest.ResponseRecorder, name string) bool {
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func itoa(v int64) string {
	return strconv.FormatInt(v, 10)
}
