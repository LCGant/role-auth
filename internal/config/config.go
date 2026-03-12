package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type HTTPConfig struct {
	Addr              string
	PublicURL         string
	CORSOrigins       []string
	AllowCredentials  bool
	HSTS              HSTSConfig
	TrustProxyHeader  bool
	ProxyTrustedCIDRs []netip.Prefix
}

type HSTSConfig struct {
	Enabled           bool
	MaxAge            int
	IncludeSubdomains bool
}

type CookieConfig struct {
	Name       string
	DeviceName string
	Domain     string
	Secure     bool
	SameSite   string
}

type Argon2Config struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

type RateLimitConfig struct {
	Requests int
	Window   time.Duration
	RedisURL string
}

type LockoutConfig struct {
	MaxAttempts int
	Window      time.Duration
	BlockFor    time.Duration
	RedisURL    string
}

type SecurityConfig struct {
	SessionTTL        time.Duration
	SessionIdleTTL    time.Duration
	SessionTouchEvery time.Duration
	DeviceTTL         time.Duration
	ResetTTL          time.Duration
	MFAStepUpMaxAge   time.Duration
	EncryptionKey     []byte
	Argon2            Argon2Config
	RateLimit         RateLimitConfig
	AuthLimit         RateLimitConfig
	ForgotLimit       RateLimitConfig
	Lockout           LockoutConfig
	InternalToken     string
	EmailIssueToken   string
	EmailIssueEnabled bool
	MetricsToken      string
	DefaultTenant     string
}

type MailConfig struct {
	OutboxDir                    string
	SMTPHost                     string
	SMTPPort                     int
	SMTPUsername                 string
	SMTPPassword                 string
	SMTPFrom                     string
	SMTPRequireTLS               bool
	EmailVerificationURLTemplate string
	PasswordResetURLTemplate     string
}

type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
}

type OAuthConfig struct {
	Google  OAuthProviderConfig
	Spotify OAuthProviderConfig
}

type NotificationConfig struct {
	BaseURL       string
	InternalToken string
	Timeout       time.Duration
	AllowInsecure bool
}

type AuditConfig struct {
	BaseURL       string
	InternalToken string
	SpoolDir      string
	Timeout       time.Duration
	AllowInsecure bool
}

type Config struct {
	HTTP         HTTPConfig
	Database     string
	Cookie       CookieConfig
	Security     SecurityConfig
	Mail         MailConfig
	Notification NotificationConfig
	Audit        AuditConfig
	OAuth        OAuthConfig
	LogLevel     string
}

func Load() (Config, error) {
	cfg := Config{
		HTTP: HTTPConfig{
			Addr:             getEnvDefault("PORT", ":8080"),
			PublicURL:        getEnvDefault("PUBLIC_URL", "http://localhost:8080"),
			CORSOrigins:      splitEnv("CORS_ALLOWED_ORIGINS"),
			AllowCredentials: getEnvBool("CORS_ALLOW_CREDENTIALS", true),
			HSTS: HSTSConfig{
				Enabled:           getEnvBool("HSTS_ENABLED", false),
				MaxAge:            int(getEnvUint32("HSTS_MAX_AGE", 31536000)),
				IncludeSubdomains: getEnvBool("HSTS_INCLUDE_SUBDOMAINS", true),
			},
			TrustProxyHeader:  getEnvBool("TRUST_PROXY_HEADER", false),
			ProxyTrustedCIDRs: parseCIDRs(splitEnv("PROXY_TRUSTED_CIDRS")),
		},
		Database: os.Getenv("DATABASE_URL"),
		Cookie: CookieConfig{
			Name:       getEnvDefault("COOKIE_NAME", "session_id"),
			DeviceName: getEnvDefault("DEVICE_COOKIE_NAME", "device_id"),
			Domain:     os.Getenv("COOKIE_DOMAIN"),
			Secure:     getEnvBool("COOKIE_SECURE", true),
			SameSite:   getEnvDefault("COOKIE_SAMESITE", "Lax"),
		},
		Security: SecurityConfig{
			SessionTTL:        getEnvDuration("SESSION_TTL", 24*time.Hour*7),
			SessionIdleTTL:    getEnvDuration("SESSION_IDLE_TTL", 24*time.Hour),
			SessionTouchEvery: getEnvDuration("SESSION_TOUCH_EVERY", 2*time.Minute),
			DeviceTTL:         getEnvDuration("DEVICE_TTL", 24*time.Hour*180),
			ResetTTL:          getEnvDuration("RESET_TTL", time.Hour),
			MFAStepUpMaxAge:   getEnvDuration("MFA_STEPUP_MAX_AGE", 10*time.Minute),
			Argon2: Argon2Config{
				Memory:      getEnvUint32("ARGON2_MEMORY", 64*1024),
				Iterations:  getEnvUint32("ARGON2_ITERATIONS", 3),
				Parallelism: uint8(getEnvUint32("ARGON2_PARALLELISM", 4)),
				SaltLength:  getEnvUint32("ARGON2_SALT_LENGTH", 16),
				KeyLength:   getEnvUint32("ARGON2_KEY_LENGTH", 32),
			},
			RateLimit: RateLimitConfig{
				Requests: int(getEnvUint32("RATE_LIMIT_REQUESTS", 10)),
				Window:   getEnvDuration("RATE_LIMIT_WINDOW", time.Minute),
				RedisURL: os.Getenv("RATE_LIMIT_REDIS_URL"),
			},
			AuthLimit: RateLimitConfig{
				Requests: int(getEnvUint32("AUTH_RATE_LIMIT_REQUESTS", 8)),
				Window:   getEnvDuration("AUTH_RATE_LIMIT_WINDOW", time.Minute),
				RedisURL: os.Getenv("AUTH_RATE_LIMIT_REDIS_URL"),
			},
			ForgotLimit: RateLimitConfig{
				Requests: int(getEnvUint32("FORGOT_RATE_LIMIT_REQUESTS", 5)),
				Window:   getEnvDuration("FORGOT_RATE_LIMIT_WINDOW", 5*time.Minute),
				RedisURL: os.Getenv("FORGOT_RATE_LIMIT_REDIS_URL"),
			},
			Lockout: LockoutConfig{
				MaxAttempts: int(getEnvUint32("LOCKOUT_MAX_ATTEMPTS", 5)),
				Window:      getEnvDuration("LOCKOUT_WINDOW", 15*time.Minute),
				BlockFor:    getEnvDuration("LOCKOUT_BLOCK_FOR", 15*time.Minute),
				RedisURL:    os.Getenv("LOCKOUT_REDIS_URL"),
			},
			InternalToken:     getEnvDefault("AUTH_INTERNAL_TOKEN", ""),
			EmailIssueToken:   getEnvDefault("AUTH_EMAIL_VERIFICATION_INTERNAL_TOKEN", ""),
			EmailIssueEnabled: getEnvBool("AUTH_ENABLE_INTERNAL_EMAIL_ISSUE", false),
			MetricsToken:      getEnvDefault("AUTH_METRICS_TOKEN", ""),
			DefaultTenant:     getEnvDefault("DEFAULT_TENANT_ID", "default"),
		},
		Mail: MailConfig{
			OutboxDir:                    os.Getenv("EMAIL_OUTBOX_DIR"),
			SMTPHost:                     os.Getenv("SMTP_HOST"),
			SMTPPort:                     int(getEnvUint32("SMTP_PORT", 587)),
			SMTPUsername:                 os.Getenv("SMTP_USERNAME"),
			SMTPPassword:                 os.Getenv("SMTP_PASSWORD"),
			SMTPFrom:                     os.Getenv("SMTP_FROM"),
			SMTPRequireTLS:               getEnvBool("SMTP_REQUIRE_TLS", true),
			EmailVerificationURLTemplate: os.Getenv("EMAIL_VERIFICATION_URL_TEMPLATE"),
			PasswordResetURLTemplate:     os.Getenv("PASSWORD_RESET_URL_TEMPLATE"),
		},
		Notification: NotificationConfig{
			BaseURL:       strings.TrimSpace(os.Getenv("NOTIFICATION_BASE_URL")),
			InternalToken: strings.TrimSpace(os.Getenv("NOTIFICATION_INTERNAL_TOKEN")),
			Timeout:       getEnvDuration("NOTIFICATION_TIMEOUT", 10*time.Second),
			AllowInsecure: getEnvBool("NOTIFICATION_ALLOW_INSECURE_HTTP", false),
		},
		Audit: AuditConfig{
			BaseURL:       strings.TrimSpace(os.Getenv("AUDIT_BASE_URL")),
			InternalToken: strings.TrimSpace(os.Getenv("AUDIT_INTERNAL_TOKEN")),
			SpoolDir:      strings.TrimSpace(getEnvDefault("AUDIT_SPOOL_DIR", filepath.Join(os.TempDir(), "auth-audit-spool"))),
			Timeout:       getEnvDuration("AUDIT_TIMEOUT", 5*time.Second),
			AllowInsecure: getEnvBool("AUDIT_ALLOW_INSECURE_HTTP", false),
		},
		OAuth: OAuthConfig{
			Google: OAuthProviderConfig{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			},
			Spotify: OAuthProviderConfig{
				ClientID:     os.Getenv("SPOTIFY_CLIENT_ID"),
				ClientSecret: os.Getenv("SPOTIFY_CLIENT_SECRET"),
				RedirectURL:  os.Getenv("SPOTIFY_REDIRECT_URL"),
			},
		},
		LogLevel: getEnvDefault("LOG_LEVEL", "info"),
	}

	if cfg.Database == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if cfg.Cookie.DeviceName == "" {
		return Config{}, errors.New("DEVICE_COOKIE_NAME is required")
	}
	if cfg.Security.SessionIdleTTL <= 0 {
		return Config{}, errors.New("SESSION_IDLE_TTL must be positive")
	}
	if cfg.Security.SessionIdleTTL > cfg.Security.SessionTTL {
		return Config{}, errors.New("SESSION_IDLE_TTL cannot exceed SESSION_TTL")
	}
	if cfg.Security.SessionTouchEvery < 0 {
		return Config{}, errors.New("SESSION_TOUCH_EVERY cannot be negative")
	}
	if cfg.Security.DeviceTTL <= 0 {
		return Config{}, errors.New("DEVICE_TTL must be positive")
	}
	if cfg.Mail.OutboxDir != "" && cfg.Mail.SMTPHost != "" {
		return Config{}, errors.New("EMAIL_OUTBOX_DIR and SMTP_HOST are mutually exclusive")
	}
	if cfg.Notification.BaseURL != "" && cfg.Notification.InternalToken == "" {
		return Config{}, errors.New("NOTIFICATION_INTERNAL_TOKEN is required when NOTIFICATION_BASE_URL is set")
	}
	if cfg.Notification.BaseURL == "" && cfg.Notification.InternalToken != "" {
		return Config{}, errors.New("NOTIFICATION_BASE_URL is required when NOTIFICATION_INTERNAL_TOKEN is set")
	}
	if err := validateInternalServiceURL(cfg.Notification.BaseURL, cfg.Notification.AllowInsecure); err != nil {
		return Config{}, fmt.Errorf("invalid NOTIFICATION_BASE_URL: %w", err)
	}
	if cfg.Audit.BaseURL != "" && cfg.Audit.InternalToken == "" {
		return Config{}, errors.New("AUDIT_INTERNAL_TOKEN is required when AUDIT_BASE_URL is set")
	}
	if cfg.Audit.BaseURL == "" && cfg.Audit.InternalToken != "" {
		return Config{}, errors.New("AUDIT_BASE_URL is required when AUDIT_INTERNAL_TOKEN is set")
	}
	if err := validateInternalServiceURL(cfg.Audit.BaseURL, cfg.Audit.AllowInsecure); err != nil {
		return Config{}, fmt.Errorf("invalid AUDIT_BASE_URL: %w", err)
	}
	if cfg.Security.EmailIssueEnabled {
		if strings.TrimSpace(cfg.Security.EmailIssueToken) == "" {
			return Config{}, errors.New("AUTH_ENABLE_INTERNAL_EMAIL_ISSUE=true requires AUTH_EMAIL_VERIFICATION_INTERNAL_TOKEN")
		}
		if strings.TrimSpace(cfg.Mail.OutboxDir) == "" {
			return Config{}, errors.New("AUTH_ENABLE_INTERNAL_EMAIL_ISSUE=true requires EMAIL_OUTBOX_DIR")
		}
	}
	if cfg.Mail.SMTPHost != "" {
		if cfg.Mail.SMTPPort <= 0 || cfg.Mail.SMTPPort > 65535 {
			return Config{}, errors.New("SMTP_PORT must be between 1 and 65535")
		}
		if strings.TrimSpace(cfg.Mail.SMTPFrom) == "" {
			return Config{}, errors.New("SMTP_FROM is required when SMTP_HOST is set")
		}
		if (cfg.Mail.SMTPUsername == "") != (cfg.Mail.SMTPPassword == "") {
			return Config{}, errors.New("SMTP_USERNAME and SMTP_PASSWORD must be set together")
		}
	}

	if cfg.HTTP.TrustProxyHeader && len(cfg.HTTP.ProxyTrustedCIDRs) == 0 {
		// Fail-close to prevent IP spoofing via X-Forwarded-For without explicit trust.
		return Config{}, errors.New("TRUST_PROXY_HEADER=true requires PROXY_TRUSTED_CIDRS")
	}

	keyB64 := os.Getenv("ENCRYPTION_KEY")
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(key) != 32 {
		return Config{}, fmt.Errorf("ENCRYPTION_KEY must be 32 bytes base64: %w", err)
	}
	cfg.Security.EncryptionKey = key

	return cfg, nil
}

func getEnvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		val, err := strconv.ParseBool(v)
		if err == nil {
			return val
		}
	}
	return fallback
}

func getEnvUint32(key string, fallback uint32) uint32 {
	if v := os.Getenv(key); v != "" {
		val, err := strconv.ParseUint(v, 10, 32)
		if err == nil {
			return uint32(val)
		}
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return fallback
}

func splitEnv(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseCIDRs(list []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, cidr := range list {
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err == nil {
			out = append(out, p)
		}
	}
	return out
}

func validateInternalServiceURL(raw string, allowInsecure bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := strings.TrimSpace(u.Hostname())
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopbackHost(host) {
			return nil
		}
		return errors.New("remote http requires explicit NOTIFICATION_ALLOW_INSECURE_HTTP/AUDIT_ALLOW_INSECURE_HTTP opt-in")
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
