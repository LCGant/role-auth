package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

type oauthLinkRequest struct {
	CurrentPassword  string `json:"current_password"`
	ReauthTOTPCode   string `json:"reauth_totp_code"`
	ReauthBackupCode string `json:"reauth_backup_code"`
}

type oauthLoginCompleteRequest struct {
	TOTPCode   string `json:"totp_code"`
	BackupCode string `json:"backup_code"`
}

func (s *Server) handleOAuthStart(provider string, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var userID *int64
		if action == "link" {
			authUser, ok := s.requireUser(w, r)
			if !ok {
				return
			}
			userID = &authUser.User.ID
			var req oauthLinkRequest
			if r.ContentLength > 0 {
				if err := readJSON(r, &req); err != nil {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
					return
				}
			}
			if !s.requireSensitiveReauth(w, r, authUser, sensitiveReauthPayload{
				CurrentPassword: req.CurrentPassword,
				TOTPCode:        req.ReauthTOTPCode,
				BackupCode:      req.ReauthBackupCode,
			}) {
				return
			}
		}

		stateToken, verifier, err := s.createOAuthStateTokens()
		if err != nil {
			http.Error(w, "oauth unavailable", http.StatusBadRequest)
			return
		}

		var redirect string
		var nonce string
		switch provider {
		case "google":
			if s.google == nil {
				http.Error(w, "google oauth not configured", http.StatusNotFound)
				return
			}
			challenge := codeChallenge(verifier)
			nonce, _, err = security.GenerateToken(16)
			if err != nil {
				http.Error(w, "oauth unavailable", http.StatusBadRequest)
				return
			}
			redirect = s.google.AuthCodeURL(stateToken, challenge, nonce)
		case "spotify":
			if s.spotify == nil {
				http.Error(w, "spotify oauth not configured", http.StatusNotFound)
				return
			}
			challenge := codeChallenge(verifier)
			redirect = s.spotify.AuthCodeURL(stateToken, challenge)
		default:
			http.Error(w, "unknown provider", http.StatusBadRequest)
			return
		}

		record := store.OAuthState{
			State:        stateToken,
			Provider:     provider,
			Action:       action,
			UserID:       userID,
			CodeVerifier: verifier,
			Nonce:        nonce,
			ExpiresAt:    time.Now().Add(10 * time.Minute),
		}
		if err := s.auth.SaveOAuthState(r.Context(), record); err != nil {
			http.Error(w, "oauth state failed", http.StatusInternalServerError)
			return
		}
		setOAuthStateCookie(w, s.cfg, stateToken)
		http.Redirect(w, r, redirect, http.StatusFound)
	}
}

func (s *Server) handleOAuthCallback(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stateParam := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if stateParam == "" || code == "" {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		stateCookie, err := r.Cookie("oauth_state")
		if err != nil || stateCookie.Value == "" || !security.ConstantTimeEqualHash(stateCookie.Value, stateParam) {
			clearOAuthStateCookie(w, s.cfg)
			http.Error(w, "state invalid", http.StatusBadRequest)
			return
		}
		defer clearOAuthStateCookie(w, s.cfg)
		state, err := s.auth.ConsumeOAuthState(r.Context(), stateParam)
		if err != nil || state == nil || state.Provider != provider {
			http.Error(w, "state invalid", http.StatusBadRequest)
			return
		}

		switch provider {
		case "google":
			if s.google == nil {
				http.Error(w, "google oauth not configured", http.StatusNotFound)
				return
			}
			token, err := s.google.Exchange(r.Context(), code, state.CodeVerifier)
			if err != nil {
				http.Error(w, "exchange failed", http.StatusUnauthorized)
				return
			}
			profile, err := s.google.VerifyIDToken(r.Context(), token, state.Nonce)
			if err != nil {
				http.Error(w, "id token invalid", http.StatusUnauthorized)
				return
			}
			s.handleOAuthResult(w, r, state, "google", profile.Subject, profile.Email, profile.EmailVerified)
		case "spotify":
			if s.spotify == nil {
				http.Error(w, "spotify oauth not configured", http.StatusNotFound)
				return
			}
			token, err := s.spotify.Exchange(r.Context(), code, state.CodeVerifier)
			if err != nil {
				http.Error(w, "exchange failed", http.StatusUnauthorized)
				return
			}
			profile, err := s.spotify.Profile(r.Context(), token)
			if err != nil {
				http.Error(w, "profile fetch failed", http.StatusUnauthorized)
				return
			}
			s.handleOAuthResult(w, r, state, "spotify", profile.ID, profile.Email, false)
		default:
			http.Error(w, "unknown provider", http.StatusBadRequest)
		}
	}
}

func (s *Server) handleOAuthResult(w http.ResponseWriter, r *http.Request, state *store.OAuthState, provider, subject, email string, emailVerified bool) {
	if state.Action == "link" {
		authUser, ok := s.requireUser(w, r)
		if !ok {
			return
		}
		if state.UserID == nil || *state.UserID != authUser.User.ID {
			http.Error(w, "reauth required", http.StatusUnauthorized)
			return
		}
		// The step-up challenge is enforced on /oauth/*/link start and bound to this
		// callback via consumed oauth_state + matching authenticated user.
		if err := s.auth.LinkIdentity(r.Context(), authUser.User.ID, provider, subject, email, emailVerified); err != nil {
			http.Error(w, "cannot link", http.StatusBadRequest)
			return
		}
		s.auth.LogEvent(r.Context(), "oauth-link", &authUser.User.ID, provider, clientIP(r, s.cfg), r.UserAgent(), true)
		writeJSON(w, http.StatusOK, map[string]any{"linked": provider})
		return
	}

	result, err := s.auth.LoginWithOAuth(
		r.Context(),
		provider,
		subject,
		email,
		emailVerified,
		clientIP(r, s.cfg),
		r.UserAgent(),
		auth.DeviceBinding{
			Token:        deviceTokenFromRequest(r, s.cfg),
			ClientFamily: clientFamilyFromRequest(r),
		},
	)
	if err != nil {
		if err == auth.ErrOAuthProvisioning {
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	if result.RequiresMFA {
		setOAuthLoginPendingCookie(w, s.cfg, result.PendingState)
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"mfa_required": true,
			"provider":     provider,
		})
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
		"provider":   provider,
		"csrf_token": result.CSRFToken,
	})
}

func (s *Server) handleOAuthUnlink(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authUser, ok := s.requireUser(w, r)
		if !ok {
			return
		}
		var req oauthLinkRequest
		if r.ContentLength > 0 {
			if err := readJSON(r, &req); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
				return
			}
		}
		if !s.requireSensitiveReauth(w, r, authUser, sensitiveReauthPayload{
			CurrentPassword: req.CurrentPassword,
			TOTPCode:        req.ReauthTOTPCode,
			BackupCode:      req.ReauthBackupCode,
		}) {
			return
		}
		if err := s.auth.UnlinkIdentity(r.Context(), authUser.User.ID, provider); err != nil {
			http.Error(w, "cannot unlink", http.StatusBadRequest)
			return
		}
		s.auth.LogEvent(r.Context(), "oauth-unlink", &authUser.User.ID, provider, clientIP(r, s.cfg), r.UserAgent(), true)
		writeJSON(w, http.StatusOK, map[string]any{"unlinked": provider})
	}
}

func (s *Server) handleOAuthLoginComplete(w http.ResponseWriter, r *http.Request) {
	var req oauthLoginCompleteRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	pendingCookie, err := r.Cookie("oauth_login_pending")
	if err != nil || pendingCookie.Value == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	result, provider, err := s.auth.CompleteOAuthLogin(
		r.Context(),
		pendingCookie.Value,
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
		switch err {
		case auth.ErrInvalidMFA, auth.ErrMFARequired:
			writeJSON(w, http.StatusUnauthorized, map[string]any{"mfa_required": true, "error": "invalid_mfa"})
			return
		case auth.ErrInvalidToken:
			clearOAuthLoginPendingCookie(w, s.cfg)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		default:
			http.Error(w, "login failed", http.StatusUnauthorized)
			return
		}
	}
	clearOAuthLoginPendingCookie(w, s.cfg)
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
		"provider":   provider,
		"csrf_token": result.CSRFToken,
	})
}

func (s *Server) createOAuthStateTokens() (state string, verifier string, err error) {
	state, _, err = security.GenerateToken(24)
	if err != nil {
		return "", "", err
	}
	verifier, _, err = security.GenerateToken(32)
	if err != nil {
		return "", "", err
	}
	return state, verifier, nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
