package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/config"
	"github.com/LCGant/role-auth/internal/security"
	"github.com/LCGant/role-auth/internal/store"
)

type totpSetupResponse struct {
	Secret          string `json:"secret"`
	ProvisioningURI string `json:"provisioning_uri"`
}

type totpSetupRequest struct {
	CurrentPassword string `json:"current_password"`
}

type totpVerifyRequest struct {
	Code             string `json:"code"`
	CurrentPassword  string `json:"current_password"`
	ReauthTOTPCode   string `json:"reauth_totp_code"`
	ReauthBackupCode string `json:"reauth_backup_code"`
}

func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	req := totpSetupRequest{}
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
	}
	if !s.requireSensitiveReauth(w, r, authUser, sensitiveReauthPayload{
		CurrentPassword: req.CurrentPassword,
	}) {
		return
	}
	secret, uri, err := s.auth.SetupTOTP(r.Context(), authUser.User.ID, authUser.User.Email, "role-auth")
	if err != nil {
		http.Error(w, "cannot setup", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, totpSetupResponse{Secret: secret, ProvisioningURI: uri})
}

func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req totpVerifyRequest
	if err := readJSON(r, &req); err != nil || req.Code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	if !s.requireSensitiveReauth(w, r, authUser, sensitiveReauthPayload{
		CurrentPassword: req.CurrentPassword,
		TOTPCode:        req.ReauthTOTPCode,
		BackupCode:      req.ReauthBackupCode,
	}) {
		return
	}
	codes, rotation, err := s.auth.ConfirmTOTPAndReissue(r.Context(), authUser.User.ID, req.Code, authUser.Session.TokenHash)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_mfa"})
		return
	}
	applySessionRotation(w, s.cfg, authUser, rotation)
	s.auth.LogEvent(r.Context(), "mfa-enable", &authUser.User.ID, "", clientIP(r, s.cfg), r.UserAgent(), true)
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req sensitiveReauthPayload
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
	}
	if !s.requireSensitiveReauth(w, r, authUser, req) {
		return
	}
	rotation, err := s.auth.DisableTOTPAndReissue(r.Context(), authUser.User.ID, authUser.Session.TokenHash)
	if err != nil {
		http.Error(w, "cannot disable", http.StatusInternalServerError)
		return
	}
	applySessionRotation(w, s.cfg, authUser, rotation)
	s.auth.LogEvent(r.Context(), "mfa-disable", &authUser.User.ID, "", clientIP(r, s.cfg), r.UserAgent(), true)
	writeJSON(w, http.StatusOK, map[string]any{"disabled": true})
}

func (s *Server) handleBackupRegenerate(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	var req sensitiveReauthPayload
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
			return
		}
	}
	if !s.requireSensitiveReauth(w, r, authUser, req) {
		return
	}
	codes, err := s.auth.RegenerateBackupCodes(r.Context(), authUser.User.ID)
	if err != nil {
		http.Error(w, "cannot regenerate", http.StatusInternalServerError)
		return
	}
	s.auth.LogEvent(r.Context(), "backup-regenerate", &authUser.User.ID, "", clientIP(r, s.cfg), r.UserAgent(), true)
	writeJSON(w, http.StatusOK, map[string]any{"backup_codes": codes})
}

func (s *Server) requireSensitiveReauth(w http.ResponseWriter, r *http.Request, authUser *authenticatedUser, payload sensitiveReauthPayload) bool {
	if authUser == nil || authUser.User == nil || authUser.Session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	payload = payload.withHeaderFallback(r)
	if s.hasFreshPrivilegedSession(authUser.Session) {
		return true
	}
	if authUser.User.MFAEnabled {
		if err := s.auth.VerifyMFAChallenge(r.Context(), authUser.User.ID, payload.TOTPCode, payload.BackupCode); err != nil {
			http.Error(w, "mfa required", http.StatusUnauthorized)
			return false
		}
		return s.reissueSession(w, r, authUser, authUser.Session.AAL, false)
	}
	if !authUser.User.PasswordAuthEnabled {
		if s.hasFreshPrimarySession(authUser.Session) {
			return true
		}
		http.Error(w, "reauth required", http.StatusUnauthorized)
		return false
	}
	if strings.TrimSpace(payload.CurrentPassword) == "" {
		http.Error(w, "reauth required", http.StatusUnauthorized)
		return false
	}
	if err := s.auth.VerifyPasswordChallenge(r.Context(), authUser.User.ID, payload.CurrentPassword); err != nil {
		http.Error(w, "reauth required", http.StatusUnauthorized)
		return false
	}
	return s.reissueSession(w, r, authUser, authUser.Session.AAL, false)
}

func (s *Server) hasFreshPrivilegedSession(session *store.Session) bool {
	if session == nil || session.AAL < 2 || session.RiskScore > 50 {
		return false
	}
	maxAge := s.cfg.Security.MFAStepUpMaxAge
	if maxAge <= 0 {
		return true
	}
	authTime := sessionAuthTime(session)
	if authTime.IsZero() {
		return false
	}
	age := time.Since(authTime)
	return age >= 0 && age <= maxAge
}

func (s *Server) hasFreshPrimarySession(session *store.Session) bool {
	if session == nil || session.RiskScore > 50 {
		return false
	}
	maxAge := s.cfg.Security.MFAStepUpMaxAge
	authTime := sessionAuthTime(session)
	if authTime.IsZero() {
		return false
	}
	if maxAge <= 0 {
		return true
	}
	age := time.Since(authTime)
	return age >= 0 && age <= maxAge
}

func (s *Server) reissueSession(w http.ResponseWriter, r *http.Request, authUser *authenticatedUser, aal int, revokeOtherSessions bool) bool {
	if authUser == nil || authUser.Session == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	rotation, err := s.auth.ReissueSession(r.Context(), authUser.User.ID, authUser.Session.TokenHash, aal, revokeOtherSessions)
	if err != nil {
		http.Error(w, "cannot rotate session", http.StatusInternalServerError)
		return false
	}
	applySessionRotation(w, s.cfg, authUser, rotation)
	return true
}

func applySessionRotation(w http.ResponseWriter, cfg config.Config, authUser *authenticatedUser, rotation *auth.SessionReissueResult) {
	if authUser == nil || authUser.Session == nil || rotation == nil {
		return
	}
	setSessionCookie(w, cfg, rotation.SessionToken)
	setCSRFCookie(w, cfg, rotation.CSRFToken)
	authUser.Session.TokenHash = security.HashToken(rotation.SessionToken)
	authUser.Session.AuthTime = rotation.AuthTime
	authUser.Session.AAL = rotation.AAL
}

func sessionAuthTime(session *store.Session) time.Time {
	if session == nil {
		return time.Time{}
	}
	if !session.AuthTime.IsZero() {
		return session.AuthTime
	}
	return session.CreatedAt
}
