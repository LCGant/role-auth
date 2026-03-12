package handlers

import (
	"context"
	"expvar"
	"log/slog"
	"net"
	"net/http"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/mail"
	"github.com/LCGant/role-auth/internal/oauth/providers"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

type Server struct {
	auth          *auth.Service
	cfg           config.Config
	logger        *slog.Logger
	limiter       Limiter
	authLimiter   Limiter
	forgotLimiter Limiter
	emailLimiter  Limiter
	google        *providers.GoogleProvider
	spotify       *providers.SpotifyProvider
	verifier      mail.VerificationSender
	mux           *http.ServeMux
}

func NewServer(cfg config.Config, logger *slog.Logger, authService *auth.Service) *Server {
	s := &Server{
		auth:          authService,
		cfg:           cfg,
		logger:        logger,
		limiter:       newLimiterFromConfig(cfg.Security.RateLimit),
		authLimiter:   newLimiterFromConfig(cfg.Security.AuthLimit),
		forgotLimiter: newLimiterFromConfig(cfg.Security.ForgotLimit),
		emailLimiter:  newRecipientLimiterFromConfig(cfg.Security.ForgotLimit),
		verifier:      mail.NewVerificationSender(cfg),
		mux:           http.NewServeMux(),
	}
	if cfg.OAuth.Google.ClientID != "" {
		if gp, err := providers.NewGoogle(context.Background(), cfg.OAuth.Google); err == nil {
			s.google = gp
		} else {
			logger.Error("google provider init failed", "err", err)
		}
	}
	if cfg.OAuth.Spotify.ClientID != "" {
		s.spotify = providers.NewSpotify(cfg.OAuth.Spotify)
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.mux.Handle("/metrics", noStore(metricsGuard(s.cfg)(expvar.Handler())))
	s.mux.Handle("POST /internal/sessions/introspect", http.HandlerFunc(s.handleIntrospect))
	if s.internalEmailIssueEnabled() {
		s.mux.Handle("POST /internal/email-verifications/issue", http.HandlerFunc(s.handleInternalEmailVerificationIssue))
	}
	s.mux.Handle("POST /register", RateLimit(s.authLimiter, s.cfg)(http.HandlerFunc(s.handleRegister)))
	s.mux.Handle("POST /login", RateLimit(s.authLimiter, s.cfg)(http.HandlerFunc(s.handleLogin)))
	s.mux.Handle("POST /email/verify/request", RateLimit(s.forgotLimiter, s.cfg)(http.HandlerFunc(s.handleEmailVerificationRequest)))
	s.mux.Handle("POST /email/verify/confirm", http.HandlerFunc(s.handleEmailVerificationConfirm))
	s.mux.Handle("POST /logout", http.HandlerFunc(s.handleLogout))
	s.mux.Handle("GET /me", http.HandlerFunc(s.handleMe))
	s.mux.Handle("GET /sessions", http.HandlerFunc(s.handleSessionsList))
	s.mux.Handle("POST /sessions/revoke-others", http.HandlerFunc(s.handleRevokeOtherSessions))
	s.mux.Handle("POST /sessions/{id}/revoke", http.HandlerFunc(s.handleSessionRevoke))
	s.mux.Handle("GET /devices", http.HandlerFunc(s.handleDevicesList))
	s.mux.Handle("POST /devices/{id}/revoke", http.HandlerFunc(s.handleDeviceRevoke))

	s.mux.Handle("GET /oauth/google/start", http.HandlerFunc(s.handleOAuthStart("google", "login")))
	s.mux.Handle("GET /oauth/google/callback", http.HandlerFunc(s.handleOAuthCallback("google")))
	s.mux.Handle("POST /oauth/google/link", http.HandlerFunc(s.handleOAuthStart("google", "link")))
	s.mux.Handle("POST /oauth/google/unlink", http.HandlerFunc(s.handleOAuthUnlink("google")))

	s.mux.Handle("GET /oauth/spotify/start", http.HandlerFunc(s.handleOAuthStart("spotify", "login")))
	s.mux.Handle("GET /oauth/spotify/callback", http.HandlerFunc(s.handleOAuthCallback("spotify")))
	s.mux.Handle("POST /oauth/spotify/link", http.HandlerFunc(s.handleOAuthStart("spotify", "link")))
	s.mux.Handle("POST /oauth/spotify/unlink", http.HandlerFunc(s.handleOAuthUnlink("spotify")))
	s.mux.Handle("POST /oauth/login/complete", http.HandlerFunc(s.handleOAuthLoginComplete))

	s.mux.Handle("POST /mfa/totp/setup", http.HandlerFunc(s.handleTOTPSetup))
	s.mux.Handle("POST /mfa/totp/verify", http.HandlerFunc(s.handleTOTPVerify))
	s.mux.Handle("POST /mfa/totp/disable", http.HandlerFunc(s.handleTOTPDisable))
	s.mux.Handle("POST /mfa/backup/regenerate", http.HandlerFunc(s.handleBackupRegenerate))

	s.mux.Handle("POST /password/forgot", http.HandlerFunc(s.handleForgotPassword))
	s.mux.Handle("POST /password/reset", http.HandlerFunc(s.handleResetPassword))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var handler http.Handler = s.mux
	handler = AuthSession(s.auth, s.cfg)(handler)
	handler = CSRFProtection(s.cfg)(handler)
	handler = CORS(s.cfg)(handler)
	handler = SecurityHeaders(s.cfg)(handler)
	handler = noStore(handler)
	handler = RateLimit(s.limiter, s.cfg)(handler)
	handler = RequestID(handler)
	handler = Recover(s.logger)(handler)
	handler = Logging(s.logger)(handler)
	handler.ServeHTTP(w, r)
}

func (s *Server) requireUser(w http.ResponseWriter, r *http.Request) (*authenticatedUser, bool) {
	userVal := r.Context().Value(ctxUserKey)
	sessionVal := r.Context().Value(ctxSessionKey)
	user, ok := userVal.(*store.User)
	session, okSess := sessionVal.(*store.Session)
	if !ok || !okSess || user == nil || session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil, false
	}
	return &authenticatedUser{User: user, Session: session}, true
}

type authenticatedUser struct {
	User    *store.User
	Session *store.Session
}

func newLimiterFromConfig(cfg config.RateLimitConfig) Limiter {
	if cfg.Requests == 0 {
		return nil
	}
	if cfg.RedisURL != "" {
		return NewRedisLimiter(cfg.RedisURL, cfg.Requests, cfg.Window)
	}
	return NewRateLimiter(cfg.Requests, cfg.Window)
}

func newRecipientLimiterFromConfig(cfg config.RateLimitConfig) Limiter {
	if cfg.Window == 0 {
		return nil
	}
	const requests = 1
	if cfg.RedisURL != "" {
		return NewRedisLimiter(cfg.RedisURL, requests, cfg.Window)
	}
	return NewRateLimiter(requests, cfg.Window)
}

func noStore(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func metricsGuard(cfg config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ip := net.ParseIP(clientIP(r, cfg)); ip != nil && ip.IsLoopback() {
				next.ServeHTTP(w, r)
				return
			}
			token := cfg.Security.MetricsToken
			headerToken := r.Header.Get("X-Metrics-Token")
			if token == "" || headerToken == "" || !security.ConstantTimeEqualHash(headerToken, token) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
