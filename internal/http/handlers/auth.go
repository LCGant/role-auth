package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

type registerRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	TOTPCode   string `json:"totp_code"`
	BackupCode string `json:"backup_code"`
}

type emailVerificationRequest struct {
	Email string `json:"email"`
}

type emailVerificationConfirmRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil || !s.verifier.Enabled() {
		http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
		return
	}
	var req registerRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	req.Username = strings.TrimSpace(req.Username)
	if !validEmail(req.Email) || !validUsername(req.Username) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user, err := s.auth.Register(r.Context(), req.Email, req.Username, req.Password, clientIP(r, s.cfg), r.UserAgent())
	if err != nil {
		http.Error(w, "cannot create user", http.StatusBadRequest)
		return
	}
	token, err := s.auth.StartEmailVerification(r.Context(), req.Email, clientIP(r, s.cfg), r.UserAgent())
	if err != nil {
		_ = s.auth.DeleteUser(r.Context(), user.ID)
		http.Error(w, "cannot create user", http.StatusInternalServerError)
		return
	}
	if err := s.sendVerificationToken(r.Context(), req.Email, token); err != nil {
		_ = s.auth.DeleteUser(r.Context(), user.ID)
		http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                          user.ID,
		"email":                       user.Email,
		"username":                    user.Username,
		"status":                      user.Status,
		"email_verification_required": true,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	req.Identifier = strings.TrimSpace(req.Identifier)
	if !validIdentifier(req.Identifier) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	result, err := s.auth.Login(
		r.Context(),
		req.Identifier,
		req.Password,
		req.TOTPCode,
		req.BackupCode,
		clientIP(r, s.cfg),
		r.UserAgent(),
		auth.DeviceBinding{
			Token:        deviceTokenFromRequest(r, s.cfg),
			ClientFamily: clientFamilyFromRequest(r),
		},
	)
	if err != nil {
		if errors.Is(err, auth.ErrLocked) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "locked"})
			return
		}
		if errors.Is(err, auth.ErrMFARequired) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"mfa_required": true})
			return
		}
		if errors.Is(err, auth.ErrInvalidMFA) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"mfa_required": true, "error": "invalid_mfa"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if result.RequiresMFA {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"mfa_required": true})
		return
	}
	setSessionCookie(w, s.cfg, result.SessionToken)
	if result.DeviceToken != "" {
		setDeviceCookie(w, s.cfg, result.DeviceToken)
	}
	setCSRFCookie(w, s.cfg, result.CSRFToken)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":       result.User.ID,
			"email":    result.User.Email,
			"username": result.User.Username,
		},
		"csrf_token": result.CSRFToken,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cfg.Cookie.Name)
	if err == nil && cookie.Value != "" {
		_ = s.auth.Logout(r.Context(), cookie.Value)
	}
	clearSessionCookie(w, s.cfg)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	userCtx := r.Context().Value(ctxUserKey)
	user, ok := userCtx.(*store.User)
	if !ok || user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                    user.ID,
		"email":                 user.Email,
		"email_verified":        user.EmailVerified,
		"username":              user.Username,
		"mfa_enabled":           user.MFAEnabled,
		"password_auth_enabled": user.PasswordAuthEnabled,
	})
}

func (s *Server) handleEmailVerificationRequest(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil || !s.verifier.Enabled() {
		http.Error(w, "verification unavailable", http.StatusServiceUnavailable)
		return
	}
	var req emailVerificationRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if !validEmail(email) {
		writeJSON(w, http.StatusAccepted, map[string]any{"message": "if the account exists, a verification email was sent"})
		return
	}
	limiter := s.emailLimiter
	if limiter == nil {
		limiter = s.forgotLimiter
	}
	if limiter != nil && !limiter.Allow(emailRateLimitKey("email-verify", email)) {
		writeJSON(w, http.StatusAccepted, map[string]any{"message": "if the account exists, a verification email was sent"})
		return
	}
	token, err := s.auth.StartEmailVerification(r.Context(), email, clientIP(r, s.cfg), r.UserAgent())
	if err != nil {
		writeJSON(w, http.StatusAccepted, map[string]any{"message": "if the account exists, a verification email was sent"})
		return
	}
	if token != "" {
		_ = s.sendVerificationToken(r.Context(), email, token)
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"message": "if the account exists, a verification email was sent"})
}

func (s *Server) handleEmailVerificationConfirm(w http.ResponseWriter, r *http.Request) {
	var req emailVerificationConfirmRequest
	if err := readJSON(r, &req); err != nil || strings.TrimSpace(req.Token) == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.auth.CompleteEmailVerification(r.Context(), req.Token, clientIP(r, s.cfg), r.UserAgent()); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "cannot verify email", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"verified": true})
}

func (s *Server) handleInternalEmailVerificationIssue(w http.ResponseWriter, r *http.Request) {
	if !s.internalEmailIssueEnabled() {
		http.Error(w, "internal disabled", http.StatusServiceUnavailable)
		return
	}
	tokenCfg := s.cfg.Security.EmailIssueToken
	headerToken := r.Header.Get("X-Internal-Token")
	if headerToken == "" || !security.ConstantTimeEqualHash(headerToken, tokenCfg) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req emailVerificationRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if !validEmail(email) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token, err := s.auth.StartEmailVerification(r.Context(), email, clientIP(r, s.cfg), r.UserAgent())
	if err != nil {
		http.Error(w, "cannot issue token", http.StatusInternalServerError)
		return
	}
	if token == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *Server) internalEmailIssueEnabled() bool {
	if !s.cfg.Security.EmailIssueEnabled {
		return false
	}
	if strings.TrimSpace(s.cfg.Security.EmailIssueToken) == "" {
		return false
	}
	return s.verifier != nil && s.verifier.SupportsInternalTokenIssue()
}

func (s *Server) sendVerificationToken(ctx context.Context, email, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("verification token missing")
	}
	if s.verifier == nil || !s.verifier.Enabled() {
		return errors.New("verification delivery unavailable")
	}
	return s.verifier.SendVerification(ctx, strings.TrimSpace(email), token)
}

func (s *Server) sendPasswordResetToken(ctx context.Context, email, token string) error {
	if strings.TrimSpace(token) == "" {
		return errors.New("password reset token missing")
	}
	if s.verifier == nil || !s.verifier.Enabled() {
		return errors.New("password reset delivery unavailable")
	}
	return s.verifier.SendPasswordReset(ctx, strings.TrimSpace(email), token)
}
