package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/LCGant/role-auth/internal/auth"
)

type forgotRequest struct {
	Email string `json:"email"`
}

type resetRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if s.verifier == nil || !s.verifier.Enabled() {
		http.Error(w, "reset unavailable", http.StatusServiceUnavailable)
		return
	}
	var req forgotRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ip := clientIP(r, s.cfg)
	limiter := s.forgotLimiter
	if limiter == nil {
		limiter = s.limiter
	}
	if limiter != nil && !limiter.Allow("forgot:"+ip) {
		http.Error(w, "try again later", http.StatusTooManyRequests)
		return
	}
	email := strings.TrimSpace(strings.ToLower(req.Email))
	if !validEmail(email) {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the account exists, an email was sent",
		})
		return
	}
	emailLimiter := s.emailLimiter
	if emailLimiter == nil {
		emailLimiter = limiter
	}
	if emailLimiter != nil && !emailLimiter.Allow(emailRateLimitKey("forgot", email)) {
		writeJSON(w, http.StatusOK, map[string]any{
			"message": "if the account exists, an email was sent",
		})
		return
	}
	if err := s.auth.StartPasswordResetWithDelivery(r.Context(), email, ip, r.UserAgent(), func(token string) error {
		return s.sendPasswordResetToken(r.Context(), email, token)
	}); err != nil {
		http.Error(w, "reset unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "if the account exists, an email was sent",
	})
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetRequest
	if err := readJSON(r, &req); err != nil || req.Token == "" || req.NewPassword == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.auth.CompletePasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reset": true})
}
