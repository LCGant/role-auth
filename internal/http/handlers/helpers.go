package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"unicode"

	"github.com/LCGant/role-auth/internal/config"
)

const maxJSONBodyBytes = 1 << 20 // 1 MiB

const (
	maxEmailLength      = 254
	minUsernameLength   = 3
	maxUsernameLength   = 64
	maxIdentifierLength = 254
)

type sensitiveReauthPayload struct {
	CurrentPassword string `json:"current_password,omitempty"`
	TOTPCode        string `json:"reauth_totp_code,omitempty"`
	BackupCode      string `json:"reauth_backup_code,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func readJSON(r *http.Request, v interface{}) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	if !hasJSONContentType(r) {
		return errors.New("content type must be application/json")
	}
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBodyBytes+1))
	if err != nil {
		return err
	}
	if int64(len(payload)) > maxJSONBodyBytes {
		return errors.New("request body too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}
	return nil
}

func hasJSONContentType(r *http.Request) bool {
	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

func setSessionCookie(w http.ResponseWriter, cfg config.Config, token string) {
	cookie := http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    token,
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func setDeviceCookie(w http.ResponseWriter, cfg config.Config, token string) {
	cookie := http.Cookie{
		Name:     cfg.Cookie.DeviceName,
		Value:    token,
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
		MaxAge:   int(cfg.Security.DeviceTTL.Seconds()),
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func setCSRFCookie(w http.ResponseWriter, cfg config.Config, token string) {
	cookie := http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: false, // needs to be readable by client for double-submit header
		SameSite: sameSite(cfg.Cookie.SameSite),
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func setOAuthStateCookie(w http.ResponseWriter, cfg config.Config, state string) {
	cookie := http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     oauthCookiePath(cfg),
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func setOAuthLoginPendingCookie(w http.ResponseWriter, cfg config.Config, state string) {
	cookie := http.Cookie{
		Name:     "oauth_login_pending",
		Value:    state,
		Path:     oauthCookiePath(cfg),
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func clearSessionCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    "",
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
		MaxAge:   -1,
	}
	w.Header().Add("Set-Cookie", cookie.String())
	clearCSRFCookie(w, cfg)
}

func clearDeviceCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := http.Cookie{
		Name:     cfg.Cookie.DeviceName,
		Value:    "",
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
		MaxAge:   -1,
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func clearCSRFCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Path:     "/",
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: false,
		SameSite: sameSite(cfg.Cookie.SameSite),
		MaxAge:   -1,
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func clearOAuthStateCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := http.Cookie{
		Name:     "oauth_state",
		Value:    "",
		Path:     oauthCookiePath(cfg),
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func clearOAuthLoginPendingCookie(w http.ResponseWriter, cfg config.Config) {
	cookie := http.Cookie{
		Name:     "oauth_login_pending",
		Value:    "",
		Path:     oauthCookiePath(cfg),
		Domain:   cfg.Cookie.Domain,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: true,
		SameSite: sameSite(cfg.Cookie.SameSite),
		MaxAge:   -1,
	}
	w.Header().Add("Set-Cookie", cookie.String())
}

func sameSite(v string) http.SameSite {
	switch strings.ToLower(v) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func oauthCookiePath(cfg config.Config) string {
	raw := strings.TrimSpace(cfg.HTTP.PublicURL)
	if raw == "" {
		return "/oauth"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/oauth"
	}
	p := strings.TrimSpace(u.Path)
	if p == "" || p == "/" {
		return "/oauth"
	}
	p = strings.TrimRight(p, "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p + "/oauth"
}

func publicOrigin(cfg config.Config) string {
	raw := strings.TrimSpace(cfg.HTTP.PublicURL)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func deviceTokenFromRequest(r *http.Request, cfg config.Config) string {
	if c, err := r.Cookie(cfg.Cookie.DeviceName); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	return strings.TrimSpace(r.Header.Get("X-Device-Token"))
}

func clientFamilyFromRequest(r *http.Request) string {
	value := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Client-Family")))
	switch value {
	case "browser", "web":
		return "browser"
	case "mobile_web":
		return "mobile_web"
	case "mobile_app":
		return "mobile_app"
	case "cli":
		return "cli"
	default:
		return "generic"
	}
}

func emailRateLimitKey(prefix, email string) string {
	normalized := strings.TrimSpace(strings.ToLower(email))
	if normalized == "" {
		return prefix + "|email:empty"
	}
	sum := sha256.Sum256([]byte(normalized))
	return prefix + "|email:" + hex.EncodeToString(sum[:8])
}

func extractCurrentPassword(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Current-Password"))
}

func extractHeaderMFACodes(r *http.Request) (totpCode, backupCode string) {
	return strings.TrimSpace(r.Header.Get("X-TOTP-Code")), strings.TrimSpace(r.Header.Get("X-Backup-Code"))
}

func (p sensitiveReauthPayload) withHeaderFallback(r *http.Request) sensitiveReauthPayload {
	if strings.TrimSpace(p.CurrentPassword) == "" {
		p.CurrentPassword = extractCurrentPassword(r)
	}
	headerTOTP, headerBackup := extractHeaderMFACodes(r)
	if strings.TrimSpace(p.TOTPCode) == "" {
		p.TOTPCode = headerTOTP
	}
	if strings.TrimSpace(p.BackupCode) == "" {
		p.BackupCode = headerBackup
	}
	return p
}

func validEmail(email string) bool {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > maxEmailLength {
		return false
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return false
	}
	_, err := mail.ParseAddress(email)
	return err == nil
}

func validUsername(username string) bool {
	if len(username) < minUsernameLength || len(username) > maxUsernameLength {
		return false
	}
	for _, r := range username {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
		case r == '_', r == '-', r == '.':
		default:
			return false
		}
	}
	return true
}

func validIdentifier(identifier string) bool {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" || len(identifier) > maxIdentifierLength {
		return false
	}
	if strings.ContainsAny(identifier, "\r\n\t") {
		return false
	}
	return true
}
