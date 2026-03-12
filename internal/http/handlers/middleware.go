package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/security"
)

type ctxKey string

const (
	ctxUserKey    ctxKey = "user"
	ctxSessionKey ctxKey = "session"
)

func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			incRequest()
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"duration_ms", time.Since(start).Milliseconds())
		})
	}
}

func Recover(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic", "err", rec)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = time.Now().UTC().Format("20060102T150405.000000000")
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), ctxKey("request_id"), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RateLimit(limiter Limiter, cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/healthz" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/internal/") {
				ip := clientIP(r, cfg)
				key := internalRateLimitKey(r, cfg, ip)
				if limiter != nil && !limiter.Allow(key) {
					http.Error(w, "try again later", http.StatusTooManyRequests)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			ip := clientIP(r, cfg)
			key := r.URL.Path + "|" + ip
			if limiter != nil && !limiter.Allow(key) {
				http.Error(w, "try again later", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func internalRateLimitKey(r *http.Request, cfg config.Config, ip string) string {
	token := strings.TrimSpace(r.Header.Get("X-Internal-Token"))
	if token != "" && cfg.Security.InternalToken != "" && security.ConstantTimeEqualHash(token, cfg.Security.InternalToken) {
		if clientID := strings.TrimSpace(r.Header.Get("X-Client-Id")); clientID != "" {
			return r.URL.Path + "|internal|client:" + clientID
		}
		sum := sha256.Sum256([]byte(token))
		return r.URL.Path + "|internal|token:" + hex.EncodeToString(sum[:8])
	}
	return r.URL.Path + "|internal|ip:" + ip
}

func SecurityHeaders(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			if cfg.HTTP.HSTS.Enabled {
				value := "max-age=" + strconv.Itoa(cfg.HTTP.HSTS.MaxAge)
				if cfg.HTTP.HSTS.IncludeSubdomains {
					value += "; includeSubDomains"
				}
				w.Header().Set("Strict-Transport-Security", value)
			}
			next.ServeHTTP(w, r)
		})
	}
}

func CORS(cfg config.Config) func(http.Handler) http.Handler {
	allowed := cfg.HTTP.CORSOrigins
	allowCreds := cfg.HTTP.AllowCredentials
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" || !originAllowed(origin, allowed) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Add("Vary", "Origin")
			if allowCreds {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,X-CSRF-Token,Authorization,X-Current-Password,X-TOTP-Code,X-Backup-Code,X-Client-Family,X-Device-Token,X-Requested-With")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func originAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), origin) {
			return true
		}
	}
	return false
}

func CSRFProtection(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			// Public/unauthenticated endpoints do not require CSRF even if a stray session cookie is present.
			switch r.URL.Path {
			case "/internal/sessions/introspect", "/internal/email-verifications/issue":
				next.ServeHTTP(w, r)
				return
			case "/login", "/register", "/password/reset", "/password/forgot", "/email/verify/request", "/email/verify/confirm":
				if !publicMutationOriginAllowed(r, cfg) {
					http.Error(w, "origin not allowed", http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			// Enforce double-submit for any mutating request that carries a session cookie
			// (even if the session is invalid) or has an authenticated user in context.
			sessionCookie, err := r.Cookie(cfg.Cookie.Name)
			hasSessionCookie := err == nil && sessionCookie.Value != ""
			user := r.Context().Value(ctxUserKey)
			if user == nil && !hasSessionCookie {
				next.ServeHTTP(w, r)
				return
			}
			csrfCookie, err := r.Cookie("csrf_token")
			if err != nil || csrfCookie.Value == "" {
				http.Error(w, "csrf token missing", http.StatusForbidden)
				return
			}
			header := r.Header.Get("X-CSRF-Token")
			if header == "" || !security.ConstantTimeEqualHash(header, csrfCookie.Value) {
				http.Error(w, "csrf token invalid", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func publicMutationOriginAllowed(r *http.Request, cfg config.Config) bool {
	allowedOrigins := cfg.HTTP.CORSOrigins
	if len(allowedOrigins) == 0 {
		if origin := publicOrigin(cfg); origin != "" {
			allowedOrigins = []string{origin}
		}
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		return originAllowed(origin, allowedOrigins)
	}
	ref := strings.TrimSpace(r.Header.Get("Referer"))
	if ref == "" {
		return hasExplicitAPIClientSignal(r)
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return originAllowed(u.Scheme+"://"+u.Host, allowedOrigins)
}

func hasExplicitAPIClientSignal(r *http.Request) bool {
	if clientFamilyFromRequest(r) != "generic" {
		return true
	}
	return strings.TrimSpace(r.Header.Get("X-Requested-With")) != ""
}

func AuthSession(s *auth.Service, cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cfg.Cookie.Name)
			if err != nil || cookie.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			user, session, err := s.ValidateSession(r.Context(), cookie.Value, auth.SessionValidation{
				DeviceToken:     deviceTokenFromRequest(r, cfg),
				ClientFamily:    clientFamilyFromRequest(r),
				IP:              clientIP(r, cfg),
				UserAgent:       r.UserAgent(),
				RefreshMetadata: true,
			})
			if err == nil && user != nil {
				ctx := context.WithValue(r.Context(), ctxUserKey, user)
				ctx = context.WithValue(ctx, ctxSessionKey, session)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			clearSessionCookie(w, cfg)
			next.ServeHTTP(w, r)
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
