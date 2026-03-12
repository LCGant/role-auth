package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
	"log/slog"
)

// fakeStore minimally implements auth.Store for introspection tests.
type fakeStore struct {
	users        map[int64]*store.User
	sessions     map[string]*store.Session
	devices      map[int64]*store.Device
	identities   map[string]*store.Identity
	oauthStates  map[string]store.OAuthState
	totp         map[int64]*store.MFATOTP
	backupCodes  map[int64]map[string]bool
	passwords    map[string]*store.PasswordReset
	emailVerifs  map[string]*store.EmailVerification
	deviceTokens map[int64]string
	nextUserID   int64
	nextDeviceID int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:        make(map[int64]*store.User),
		sessions:     make(map[string]*store.Session),
		devices:      make(map[int64]*store.Device),
		identities:   make(map[string]*store.Identity),
		oauthStates:  make(map[string]store.OAuthState),
		totp:         make(map[int64]*store.MFATOTP),
		backupCodes:  make(map[int64]map[string]bool),
		passwords:    make(map[string]*store.PasswordReset),
		emailVerifs:  make(map[string]*store.EmailVerification),
		deviceTokens: make(map[int64]string),
		nextUserID:   100,
		nextDeviceID: 1,
	}
}

func (f *fakeStore) CreateUser(ctx context.Context, u *store.User) error {
	if u.ID == 0 {
		u.ID = f.nextUserID
		f.nextUserID++
	}
	if u.PasswordHash != "" && !u.PasswordAuthEnabled {
		u.PasswordAuthEnabled = true
	}
	if u.Status == "" {
		u.Status = "pending_verification"
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	u.UpdatedAt = time.Now()
	f.users[u.ID] = u
	return nil
}
func (f *fakeStore) CreateUserWithIdentity(ctx context.Context, u *store.User, ident *store.Identity) error {
	if err := f.CreateUser(ctx, u); err != nil {
		return err
	}
	ident.UserID = u.ID
	return f.CreateIdentity(ctx, ident)
}
func (f *fakeStore) DeleteUserByID(ctx context.Context, id int64) error {
	delete(f.users, id)
	for tokenHash, sess := range f.sessions {
		if sess.UserID == id {
			delete(f.sessions, tokenHash)
		}
	}
	for deviceID, device := range f.devices {
		if device.UserID == id {
			delete(f.devices, deviceID)
			delete(f.deviceTokens, deviceID)
		}
	}
	return nil
}
func (f *fakeStore) FindUserByEmailOrUsername(ctx context.Context, identifier string) (*store.User, error) {
	needle := strings.ToLower(strings.TrimSpace(identifier))
	for _, u := range f.users {
		if strings.EqualFold(u.Email, needle) || strings.EqualFold(u.Username, needle) {
			return u, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) GetUserByID(ctx context.Context, id int64) (*store.User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, nil
}
func (f *fakeStore) UpdateUserPassword(ctx context.Context, userID int64, passwordHash string) error {
	if user, ok := f.users[userID]; ok {
		user.PasswordHash = passwordHash
		user.PasswordAuthEnabled = true
	}
	return nil
}
func (f *fakeStore) CreateDevice(ctx context.Context, device *store.Device) error {
	if device.ID == 0 {
		device.ID = f.nextDeviceID
		f.nextDeviceID++
	}
	now := time.Now().UTC()
	if device.FirstSeenAt.IsZero() {
		device.FirstSeenAt = now
	}
	device.LastSeenAt = now
	f.devices[device.ID] = device
	return nil
}
func (f *fakeStore) GetDeviceByTokenHash(ctx context.Context, userID int64, tokenHash string) (*store.Device, error) {
	for _, device := range f.devices {
		if device.UserID == userID && device.TokenHash == tokenHash && device.RevokedAt == nil {
			return device, nil
		}
	}
	return nil, nil
}
func (f *fakeStore) UpdateDeviceSeen(ctx context.Context, deviceID int64, clientFamily, ip, userAgent, trustLevel string, riskScore int) error {
	if device, ok := f.devices[deviceID]; ok && device.RevokedAt == nil {
		device.ClientFamily = clientFamily
		device.LastIP = ip
		device.LastUserAgent = userAgent
		device.TrustLevel = trustLevel
		device.RiskScore = riskScore
		device.LastSeenAt = time.Now().UTC()
	}
	return nil
}
func (f *fakeStore) CreateSession(ctx context.Context, sess *store.Session) error {
	if sess.AuthTime.IsZero() {
		sess.AuthTime = time.Now().UTC()
	}
	if sess.IdleExpiresAt.IsZero() {
		sess.IdleExpiresAt = sess.ExpiresAt
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now()
	}
	if sess.LastSeenAt.IsZero() {
		sess.LastSeenAt = sess.CreatedAt
	}
	if sess.AuthMethod == "" {
		sess.AuthMethod = "session"
	}
	if device, ok := f.devices[sess.DeviceID]; ok {
		sess.DeviceTrustLevel = device.TrustLevel
		sess.DeviceClientFamily = device.ClientFamily
		sess.RiskScore = device.RiskScore
	}
	f.sessions[sess.TokenHash] = sess
	return nil
}
func (f *fakeStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*store.Session, error) {
	if s, ok := f.sessions[tokenHash]; ok {
		return s, nil
	}
	return nil, nil
}
func (f *fakeStore) DeleteSessionByHash(ctx context.Context, tokenHash string) error {
	delete(f.sessions, tokenHash)
	return nil
}
func (f *fakeStore) DeleteSessionsByUserID(ctx context.Context, userID int64) error {
	for tokenHash, sess := range f.sessions {
		if sess.UserID == userID {
			delete(f.sessions, tokenHash)
		}
	}
	return nil
}
func (f *fakeStore) DeleteSessionByID(ctx context.Context, userID, sessionID int64) error {
	for tokenHash, sess := range f.sessions {
		if sess.UserID == userID && sess.ID == sessionID {
			delete(f.sessions, tokenHash)
		}
	}
	return nil
}
func (f *fakeStore) DeleteOtherSessionsByUserID(ctx context.Context, userID int64, keepTokenHash string) error {
	for tokenHash, sess := range f.sessions {
		if sess.UserID == userID && tokenHash != keepTokenHash {
			delete(f.sessions, tokenHash)
		}
	}
	return nil
}
func (f *fakeStore) TouchSession(ctx context.Context, tokenHash string, idleExpiresAt time.Time) error {
	if sess, ok := f.sessions[tokenHash]; ok {
		sess.LastSeenAt = time.Now()
		sess.IdleExpiresAt = idleExpiresAt
	}
	return nil
}

func (f *fakeStore) RotateSession(ctx context.Context, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error {
	sess, ok := f.sessions[oldTokenHash]
	if !ok {
		return errors.New("session not found")
	}
	delete(f.sessions, oldTokenHash)
	sess.TokenHash = newTokenHash
	sess.AuthTime = authTime
	sess.IdleExpiresAt = idleExpiresAt
	sess.AAL = aal
	sess.LastSeenAt = time.Now()
	if sess.DeviceID != 0 && aal >= 2 {
		if device, ok := f.devices[sess.DeviceID]; ok {
			if device.TrustLevel != "verified" {
				device.TrustLevel = "trusted"
			}
			sess.DeviceTrustLevel = device.TrustLevel
		}
	}
	f.sessions[newTokenHash] = sess
	return nil
}

func (f *fakeStore) RotateSessionAndDeleteOthers(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time, aal int) error {
	if err := f.RotateSession(ctx, oldTokenHash, newTokenHash, authTime, idleExpiresAt, aal); err != nil {
		return err
	}
	return f.DeleteOtherSessionsByUserID(ctx, userID, newTokenHash)
}
func (f *fakeStore) UpsertTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error {
	f.totp[userID] = &store.MFATOTP{
		UserID:          userID,
		EncryptedSecret: encryptedSecret,
		Nonce:           nonce,
	}
	return nil
}
func (f *fakeStore) SetPendingTOTPSecret(ctx context.Context, userID int64, encryptedSecret, nonce []byte) error {
	rec, ok := f.totp[userID]
	if !ok {
		rec = &store.MFATOTP{UserID: userID}
		f.totp[userID] = rec
	}
	now := time.Now()
	rec.PendingEncryptedSecret = encryptedSecret
	rec.PendingNonce = nonce
	rec.PendingCreatedAt = &now
	return nil
}
func (f *fakeStore) PromotePendingTOTP(ctx context.Context, userID int64) error {
	if rec, ok := f.totp[userID]; ok {
		if len(rec.PendingEncryptedSecret) > 0 && len(rec.PendingNonce) > 0 {
			rec.EncryptedSecret = rec.PendingEncryptedSecret
			rec.Nonce = rec.PendingNonce
		}
		rec.PendingEncryptedSecret = nil
		rec.PendingNonce = nil
		rec.PendingCreatedAt = nil
		rec.LastUsedAt = nil
	}
	return nil
}
func (f *fakeStore) EnableTOTP(ctx context.Context, userID int64) error {
	if rec, ok := f.totp[userID]; ok {
		now := time.Now()
		rec.EnabledAt = &now
	}
	if u, ok := f.users[userID]; ok {
		u.MFAEnabled = true
	}
	return nil
}

func (f *fakeStore) FinalizeTOTPEnrollment(ctx context.Context, userID int64, backupHashes []string, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error {
	if err := f.PromotePendingTOTP(ctx, userID); err != nil {
		return err
	}
	if err := f.EnableTOTP(ctx, userID); err != nil {
		return err
	}
	if err := f.ReplaceBackupCodes(ctx, userID, backupHashes); err != nil {
		return err
	}
	return f.RotateSessionAndDeleteOthers(ctx, userID, oldTokenHash, newTokenHash, authTime, idleExpiresAt, 2)
}

func (f *fakeStore) DisableTOTPAndRotateSession(ctx context.Context, userID int64, oldTokenHash, newTokenHash string, authTime, idleExpiresAt time.Time) error {
	delete(f.totp, userID)
	if u, ok := f.users[userID]; ok {
		u.MFAEnabled = false
	}
	delete(f.backupCodes, userID)
	return f.RotateSessionAndDeleteOthers(ctx, userID, oldTokenHash, newTokenHash, authTime, idleExpiresAt, 1)
}
func (f *fakeStore) GetTOTP(ctx context.Context, userID int64) (*store.MFATOTP, error) {
	if rec, ok := f.totp[userID]; ok {
		return rec, nil
	}
	return nil, nil
}
func (f *fakeStore) UpdateTOTPUsed(ctx context.Context, userID int64, t time.Time) error {
	if rec, ok := f.totp[userID]; ok {
		rec.LastUsedAt = &t
	}
	return nil
}
func (f *fakeStore) ReplaceBackupCodes(ctx context.Context, userID int64, hashes []string) error {
	f.backupCodes[userID] = make(map[string]bool, len(hashes))
	for _, hash := range hashes {
		f.backupCodes[userID][hash] = false
	}
	return nil
}
func (f *fakeStore) UseBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	for hash, used := range f.backupCodes[userID] {
		if used {
			continue
		}
		ok, err := security.VerifyPassword(code, hash)
		if err != nil {
			return false, err
		}
		if ok {
			f.backupCodes[userID][hash] = true
			return true, nil
		}
	}
	return false, nil
}
func (f *fakeStore) CreatePasswordReset(ctx context.Context, pr *store.PasswordReset) error {
	for hash, existing := range f.passwords {
		if existing.UserID == pr.UserID && existing.UsedAt == nil {
			delete(f.passwords, hash)
		}
	}
	if pr.ID == 0 {
		pr.ID = int64(len(f.passwords) + 1)
	}
	if pr.CreatedAt.IsZero() {
		pr.CreatedAt = time.Now().UTC()
	}
	f.passwords[pr.TokenHash] = pr
	return nil
}
func (f *fakeStore) ConsumePasswordReset(ctx context.Context, tokenHash string) (*store.PasswordReset, error) {
	reset, ok := f.passwords[tokenHash]
	if !ok {
		return nil, nil
	}
	if reset.UsedAt != nil || (!reset.ExpiresAt.IsZero() && !reset.ExpiresAt.After(time.Now())) {
		return nil, nil
	}
	now := time.Now().UTC()
	reset.UsedAt = &now
	return reset, nil
}
func (f *fakeStore) ApplyPasswordReset(ctx context.Context, tokenHash, passwordHash string) (int64, error) {
	reset, ok := f.passwords[tokenHash]
	if !ok {
		return 0, nil
	}
	if reset.UsedAt != nil || (!reset.ExpiresAt.IsZero() && !reset.ExpiresAt.After(time.Now())) {
		return 0, nil
	}
	now := time.Now().UTC()
	reset.UsedAt = &now
	if err := f.UpdateUserPassword(ctx, reset.UserID, passwordHash); err != nil {
		return 0, err
	}
	if err := f.DeletePendingPasswordResetsByUserID(ctx, reset.UserID); err != nil {
		return 0, err
	}
	if err := f.DeleteSessionsByUserID(ctx, reset.UserID); err != nil {
		return 0, err
	}
	return reset.UserID, nil
}
func (f *fakeStore) DeletePendingPasswordResetsByUserID(ctx context.Context, userID int64) error {
	for hash, reset := range f.passwords {
		if reset.UserID == userID && reset.UsedAt == nil {
			delete(f.passwords, hash)
		}
	}
	return nil
}
func (f *fakeStore) CreateEmailVerification(ctx context.Context, ev *store.EmailVerification) error {
	for hash, existing := range f.emailVerifs {
		if existing.UserID == ev.UserID && existing.UsedAt == nil {
			delete(f.emailVerifs, hash)
		}
	}
	if ev.ID == 0 {
		ev.ID = int64(len(f.emailVerifs) + 1)
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	f.emailVerifs[ev.TokenHash] = ev
	return nil
}
func (f *fakeStore) ConsumeEmailVerification(ctx context.Context, tokenHash string) (*store.EmailVerification, error) {
	ev, ok := f.emailVerifs[tokenHash]
	if !ok {
		return nil, nil
	}
	now := time.Now().UTC()
	if ev.UsedAt != nil || ev.ExpiresAt.Before(now) {
		return nil, nil
	}
	ev.UsedAt = &now
	if user, ok := f.users[ev.UserID]; ok {
		user.EmailVerified = true
		if user.Status == "pending_verification" {
			user.Status = "active"
		}
	}
	return ev, nil
}
func (f *fakeStore) CreateIdentity(ctx context.Context, ident *store.Identity) error {
	key := ident.Provider + "|" + ident.Subject
	if ident.ID == 0 {
		ident.ID = int64(len(f.identities) + 1)
	}
	ident.CreatedAt = time.Now()
	ident.LastLoginAt = ident.CreatedAt
	f.identities[key] = ident
	return nil
}
func (f *fakeStore) GetIdentity(ctx context.Context, provider, subject string) (*store.Identity, error) {
	if ident, ok := f.identities[provider+"|"+subject]; ok {
		return ident, nil
	}
	return nil, nil
}
func (f *fakeStore) UpdateIdentityLogin(ctx context.Context, id int64) error {
	for _, ident := range f.identities {
		if ident.ID == id {
			ident.LastLoginAt = time.Now()
			return nil
		}
	}
	return nil
}
func (f *fakeStore) DeleteIdentity(ctx context.Context, userID int64, provider string) error {
	for key, ident := range f.identities {
		if ident.UserID == userID && ident.Provider == provider {
			delete(f.identities, key)
		}
	}
	return nil
}
func (f *fakeStore) CountIdentitiesByUserID(ctx context.Context, userID int64) (int, error) {
	count := 0
	for _, ident := range f.identities {
		if ident.UserID == userID {
			count++
		}
	}
	return count, nil
}
func (f *fakeStore) InsertAuditLog(ctx context.Context, entry *store.AuditLog) error { return nil }
func (f *fakeStore) SaveOAuthState(ctx context.Context, state store.OAuthState) error {
	f.oauthStates[state.State] = state
	return nil
}
func (f *fakeStore) GetOAuthState(ctx context.Context, state string) (*store.OAuthState, error) {
	record, ok := f.oauthStates[state]
	if !ok {
		return nil, nil
	}
	if !record.ExpiresAt.IsZero() && record.ExpiresAt.Before(time.Now()) {
		delete(f.oauthStates, state)
		return nil, nil
	}
	return &record, nil
}
func (f *fakeStore) ConsumeOAuthState(ctx context.Context, state string) (*store.OAuthState, error) {
	record, err := f.GetOAuthState(ctx, state)
	if err != nil || record == nil {
		return nil, nil
	}
	delete(f.oauthStates, state)
	return record, nil
}
func (f *fakeStore) ListSessionsByUserID(ctx context.Context, userID int64) ([]*store.Session, error) {
	var sessions []*store.Session
	for _, sess := range f.sessions {
		if sess.UserID == userID {
			sessions = append(sessions, sess)
		}
	}
	return sessions, nil
}
func (f *fakeStore) ListDevicesByUserID(ctx context.Context, userID int64) ([]*store.Device, error) {
	var devices []*store.Device
	for _, device := range f.devices {
		if device.UserID == userID && device.RevokedAt == nil {
			devices = append(devices, device)
		}
	}
	return devices, nil
}
func (f *fakeStore) RevokeDeviceByID(ctx context.Context, userID, deviceID int64) error {
	if device, ok := f.devices[deviceID]; ok && device.UserID == userID && device.RevokedAt == nil {
		now := time.Now().UTC()
		device.RevokedAt = &now
	}
	for tokenHash, sess := range f.sessions {
		if sess.UserID == userID && sess.DeviceID == deviceID {
			delete(f.sessions, tokenHash)
		}
	}
	return nil
}

func baseConfig() config.Config {
	return config.Config{
		Cookie: config.CookieConfig{Name: "session_id", DeviceName: "device_id", Secure: false, SameSite: "Lax"},
		Security: config.SecurityConfig{
			SessionTTL:        time.Hour,
			SessionIdleTTL:    time.Hour,
			SessionTouchEvery: 0,
			DeviceTTL:         24 * time.Hour,
			ResetTTL:          time.Hour,
			Argon2:            config.Argon2Config{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32},
			RateLimit:         config.RateLimitConfig{},
			AuthLimit:         config.RateLimitConfig{},
			ForgotLimit:       config.RateLimitConfig{},
			Lockout:           config.LockoutConfig{},
			InternalToken:     "internal-secret",
			EmailIssueToken:   "email-secret",
			EmailIssueEnabled: true,
			DefaultTenant:     "default",
		},
		Mail: config.MailConfig{
			OutboxDir: "test-outbox",
		},
	}
}

func newAuthService(fs *fakeStore, cfg config.Config) *auth.Service {
	cfg.Security.EncryptionKey = make([]byte, 32)
	return auth.New(fs, cfg)
}

func hashPasswordForTest(t *testing.T, cfg config.Config, password string) string {
	t.Helper()
	hash, err := security.HashPassword(password, security.Argon2Params{
		Memory:      cfg.Security.Argon2.Memory,
		Iterations:  cfg.Security.Argon2.Iterations,
		Parallelism: cfg.Security.Argon2.Parallelism,
		SaltLength:  cfg.Security.Argon2.SaltLength,
		KeyLength:   cfg.Security.Argon2.KeyLength,
	})
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return hash
}

func newTestServer(fs *fakeStore, cfg config.Config) *Server {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(cfg, logger, newAuthService(fs, cfg))
}

func newSessionForTest(t *testing.T, fs *fakeStore, userID int64, aal int, authTime time.Time) (string, string) {
	t.Helper()
	rawToken, tokenHash, err := security.GenerateToken(32)
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	deviceToken, deviceTokenHash, err := security.GenerateToken(32)
	if err != nil {
		t.Fatalf("generate device token: %v", err)
	}
	if authTime.IsZero() {
		authTime = time.Now().UTC()
	}
	device := &store.Device{
		ID:            fs.nextDeviceID,
		UserID:        userID,
		TokenHash:     deviceTokenHash,
		ClientFamily:  "browser",
		TrustLevel:    "known",
		FirstSeenAt:   authTime,
		LastSeenAt:    time.Now().UTC(),
		LastIP:        "192.0.2.1",
		LastUserAgent: "",
	}
	fs.nextDeviceID++
	fs.devices[device.ID] = device
	fs.deviceTokens[device.ID] = deviceToken
	fs.sessions[tokenHash] = &store.Session{
		ID:                 int64(len(fs.sessions) + 1),
		UserID:             userID,
		DeviceID:           device.ID,
		AAL:                aal,
		TokenHash:          tokenHash,
		ExpiresAt:          time.Now().Add(time.Hour),
		IdleExpiresAt:      time.Now().Add(time.Hour),
		AuthTime:           authTime,
		CreatedAt:          authTime,
		LastSeenAt:         time.Now(),
		IP:                 device.LastIP,
		UserAgent:          device.LastUserAgent,
		AuthMethod:         "session",
		DeviceTrustLevel:   device.TrustLevel,
		DeviceClientFamily: device.ClientFamily,
	}
	return rawToken, tokenHash
}

func deviceTokenForSession(t *testing.T, fs *fakeStore, session *store.Session) string {
	t.Helper()
	token := fs.deviceTokens[session.DeviceID]
	if token == "" {
		t.Fatalf("expected device token for device %d", session.DeviceID)
	}
	return token
}

func addSessionCookies(t *testing.T, req *http.Request, cfg config.Config, fs *fakeStore, rawToken string) {
	t.Helper()
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: rawToken})
	session := findSessionByToken(t, fs, rawToken)
	if session.DeviceID != 0 {
		req.AddCookie(&http.Cookie{Name: cfg.Cookie.DeviceName, Value: deviceTokenForSession(t, fs, session)})
	}
}

func findCookieValue(t *testing.T, rr *httptest.ResponseRecorder, name string) string {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("expected cookie %q in response", name)
	return ""
}

func findSessionByToken(t *testing.T, fs *fakeStore, token string) *store.Session {
	t.Helper()
	hash := security.HashToken(token)
	sess, ok := fs.sessions[hash]
	if !ok {
		t.Fatalf("expected session for issued token")
	}
	return sess
}

func findOnlySessionForUser(t *testing.T, fs *fakeStore, userID int64) *store.Session {
	t.Helper()
	var match *store.Session
	for _, sess := range fs.sessions {
		if sess.UserID != userID {
			continue
		}
		if match != nil {
			t.Fatalf("expected exactly one session for user %d", userID)
		}
		match = sess
	}
	if match == nil {
		t.Fatalf("expected a session for user %d", userID)
	}
	return match
}

func TestIntrospectActive(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", PasswordHash: "", Status: "active", MFAEnabled: true}
	raw, _ := newSessionForTest(t, fs, 10, 2, time.Now().Add(-time.Minute))

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, findSessionByToken(t, fs, raw)))
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp introspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active || resp.Subject == nil || resp.Session == nil {
		t.Fatalf("expected active response, got %+v", resp)
	}
	if resp.Subject.AAL != 2 || resp.Subject.TenantID != "tenant-42" {
		t.Fatalf("unexpected subject: %+v", resp.Subject)
	}
}

func TestMeRejectsDeviceBoundSessionWithoutDeviceCookie(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", Status: "active", EmailVerified: true}
	rawToken, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(&http.Cookie{Name: cfg.Cookie.Name, Value: rawToken})
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without matching device cookie, got %d", rr.Code)
	}
}

func TestIntrospectUnauthorizedToken(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when internal token missing, got %d", rr.Code)
	}
}

func TestIntrospectExpiredSession(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", PasswordHash: "", Status: "active", MFAEnabled: false}
	raw, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Hour))
	for _, sess := range fs.sessions {
		if sess.UserID == 10 {
			sess.ExpiresAt = time.Now().Add(-time.Minute)
			sess.IdleExpiresAt = sess.ExpiresAt
		}
	}

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, findSessionByToken(t, fs, raw)))
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp introspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Fatalf("expected inactive, got %+v", resp)
	}
}

func TestIntrospectInactiveUserReturnsInactive(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", PasswordHash: "", Status: "disabled", MFAEnabled: false}
	raw, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, findSessionByToken(t, fs, raw)))
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp introspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Fatalf("expected inactive for disabled user, got %+v", resp)
	}
}

func TestIntrospectDoesNotInflateAALFromUserMFAFlag(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", PasswordHash: "", Status: "active", MFAEnabled: true}
	raw, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, findSessionByToken(t, fs, raw)))
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp introspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Active || resp.Subject == nil {
		t.Fatalf("expected active response, got %+v", resp)
	}
	if resp.Subject.AAL != 1 {
		t.Fatalf("expected session aal=1, got %d", resp.Subject.AAL)
	}
}

func TestIntrospectWithoutForwardedClientMetadataDoesNotMutateDevice(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", Status: "active", EmailVerified: true}
	raw, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	session := findSessionByToken(t, fs, raw)
	device := fs.devices[session.DeviceID]
	device.LastIP = "198.51.100.10"
	device.LastUserAgent = "Mozilla/5.0"
	device.RiskScore = 0
	session.IP = device.LastIP
	session.UserAgent = device.LastUserAgent
	session.RiskScore = 0

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, session))
	req.Header.Set("User-Agent", "pep/1.0")
	req.RemoteAddr = "10.0.0.20:3456"
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if device.LastIP != "198.51.100.10" {
		t.Fatalf("expected device ip to remain unchanged, got %q", device.LastIP)
	}
	if device.LastUserAgent != "Mozilla/5.0" {
		t.Fatalf("expected device user agent to remain unchanged, got %q", device.LastUserAgent)
	}
}

func TestIntrospectUsesForwardedClientMetadata(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", Status: "active", EmailVerified: true}
	raw, _ := newSessionForTest(t, fs, 10, 1, time.Now().Add(-time.Minute))
	session := findSessionByToken(t, fs, raw)
	device := fs.devices[session.DeviceID]
	device.LastIP = "198.51.100.10"
	device.LastUserAgent = "Mozilla/5.0"
	device.ClientFamily = "browser"
	session.DeviceClientFamily = "browser"

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	req.Header.Set("X-Device-Token", deviceTokenForSession(t, fs, session))
	req.Header.Set("X-Auth-Client-IP", "203.0.113.77")
	req.Header.Set("X-Auth-Client-User-Agent", "MobileApp/1.0")
	req.Header.Set("X-Auth-Client-Family", "mobile_app")
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if device.LastIP != "203.0.113.77" {
		t.Fatalf("expected forwarded ip to update device, got %q", device.LastIP)
	}
	if device.LastUserAgent != "MobileApp/1.0" {
		t.Fatalf("expected forwarded user agent to update device, got %q", device.LastUserAgent)
	}
	if device.ClientFamily != "mobile_app" {
		t.Fatalf("expected forwarded family to update device, got %q", device.ClientFamily)
	}
	if session.RiskScore == 0 {
		t.Fatalf("expected risk score to reflect metadata drift")
	}
}

func TestIntrospectRejectsLegacySessionWithoutDeviceBinding(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	raw, hash, _ := security.GenerateToken(32)
	fs.users[10] = &store.User{ID: 10, TenantID: "tenant-42", Email: "u@example.com", Username: "u", Status: "active", EmailVerified: true}
	fs.sessions[hash] = &store.Session{
		ID:         1,
		UserID:     10,
		AAL:        1,
		TokenHash:  hash,
		ExpiresAt:  time.Now().Add(time.Hour),
		CreatedAt:  time.Now().Add(-time.Minute),
		LastSeenAt: time.Now().Add(-time.Second),
	}

	srv := newTestServer(fs, cfg)
	req := httptest.NewRequest(http.MethodPost, "/internal/sessions/introspect", nil)
	req.Header.Set("X-Internal-Token", "internal-secret")
	req.Header.Set("X-Session-Token", raw)
	rr := httptest.NewRecorder()

	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var resp introspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Active {
		t.Fatalf("expected inactive response for legacy session, got %+v", resp)
	}
}

func TestInternalEmailVerificationIssueUsesDedicatedToken(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-42",
		Email:         "u@example.com",
		Username:      "u",
		Status:        "pending_verification",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/internal/email-verifications/issue", strings.NewReader(`{"email":"u@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", cfg.Security.InternalToken)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected introspection token to be rejected, got %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/internal/email-verifications/issue", strings.NewReader(`{"email":"u@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", cfg.Security.EmailIssueToken)
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected dedicated email issue token to succeed, got %d", rr.Code)
	}
}

func TestInternalEmailVerificationIssueDisabledWithoutExplicitOptIn(t *testing.T) {
	cfg := baseConfig()
	cfg.Security.EmailIssueEnabled = false
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-42",
		Email:         "u@example.com",
		Username:      "u",
		Status:        "pending_verification",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	req := httptest.NewRequest(http.MethodPost, "/internal/email-verifications/issue", strings.NewReader(`{"email":"u@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", cfg.Security.EmailIssueToken)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected route to be unavailable without explicit opt-in, got %d", rr.Code)
	}
}

func TestEmailVerificationResendInvalidatesOlderTokens(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-1",
		Email:         "user@example.com",
		Username:      "user",
		Status:        "pending_verification",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	first, err := srv.auth.StartEmailVerification(context.Background(), "user@example.com", "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("first verification: %v", err)
	}
	second, err := srv.auth.StartEmailVerification(context.Background(), "user@example.com", "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("second verification: %v", err)
	}
	if first == second {
		t.Fatalf("expected unique verification tokens")
	}
	if err := srv.auth.CompleteEmailVerification(context.Background(), first, "192.0.2.1", "test"); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expected first token to be invalid after resend, got %v", err)
	}
	if err := srv.auth.CompleteEmailVerification(context.Background(), second, "192.0.2.1", "test"); err != nil {
		t.Fatalf("expected second token to remain valid, got %v", err)
	}
}

func TestEmailVerificationPreservesDisabledStatus(t *testing.T) {
	cfg := baseConfig()
	fs := newFakeStore()
	fs.users[10] = &store.User{
		ID:            10,
		TenantID:      "tenant-1",
		Email:         "user@example.com",
		Username:      "user",
		Status:        "disabled",
		EmailVerified: false,
	}
	srv := newTestServer(fs, cfg)

	token, err := srv.auth.StartEmailVerification(context.Background(), "user@example.com", "192.0.2.1", "test")
	if err != nil {
		t.Fatalf("start verification: %v", err)
	}
	if err := srv.auth.CompleteEmailVerification(context.Background(), token, "192.0.2.1", "test"); err != nil {
		t.Fatalf("complete verification: %v", err)
	}
	user := fs.users[10]
	if !user.EmailVerified {
		t.Fatalf("expected email_verified=true")
	}
	if user.Status != "disabled" {
		t.Fatalf("expected disabled status to be preserved, got %q", user.Status)
	}
}
