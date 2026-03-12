package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/LCGant/role-auth/internal/auth"
	"github.com/LCGant/role-auth/internal/security"
)

type introspectResponse struct {
	Active  bool               `json:"active"`
	Subject *introspectSubject `json:"subject,omitempty"`
	Session *introspectSession `json:"session,omitempty"`
	Error   string             `json:"error,omitempty"`
}

type introspectSubject struct {
	UserID   int64  `json:"user_id"`
	TenantID string `json:"tenant_id"`
	AAL      int    `json:"aal"`
	AuthTime string `json:"auth_time"`
}

type introspectSession struct {
	ID                 int64  `json:"id"`
	DeviceID           int64  `json:"device_id,omitempty"`
	ExpiresAt          string `json:"expires_at"`
	IdleExpiresAt      string `json:"idle_expires_at"`
	LastSeenAt         string `json:"last_seen_at"`
	AuthMethod         string `json:"auth_method,omitempty"`
	RiskScore          int    `json:"risk_score,omitempty"`
	DeviceTrustLevel   string `json:"device_trust_level,omitempty"`
	DeviceClientFamily string `json:"device_client_family,omitempty"`
}

// handleIntrospect exposes an internal endpoint for PEP/gateway to check session validity.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	tokenCfg := s.cfg.Security.InternalToken
	if tokenCfg == "" {
		http.Error(w, "introspection disabled", http.StatusServiceUnavailable)
		return
	}
	headerToken := r.Header.Get("X-Internal-Token")
	if headerToken == "" || !security.ConstantTimeEqualHash(headerToken, tokenCfg) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionToken := r.Header.Get("X-Session-Token")
	if sessionToken == "" {
		if c, err := r.Cookie(s.cfg.Cookie.Name); err == nil {
			sessionToken = c.Value
		}
	}
	if sessionToken == "" {
		writeJSON(w, http.StatusUnauthorized, introspectResponse{Active: false})
		return
	}

	user, sess, err := s.auth.ValidateSession(r.Context(), sessionToken, auth.SessionValidation{
		DeviceToken:     deviceTokenFromRequest(r, s.cfg),
		ClientFamily:    introspectionClientFamily(r),
		IP:              introspectionClientIP(r),
		UserAgent:       introspectionUserAgent(r),
		RefreshMetadata: hasIntrospectionClientMetadata(r),
	})
	if err != nil || user == nil || sess == nil {
		writeJSON(w, http.StatusOK, introspectResponse{Active: false})
		return
	}

	aal := sess.AAL
	if aal <= 0 {
		aal = 1
	}
	tenant := user.TenantID
	if tenant == "" {
		tenant = s.cfg.Security.DefaultTenant
		if tenant == "" {
			tenant = "default"
		}
	}
	resp := introspectResponse{
		Active: true,
		Subject: &introspectSubject{
			UserID:   user.ID,
			TenantID: tenant,
			AAL:      aal,
			AuthTime: sessionAuthTime(sess).UTC().Format(time.RFC3339),
		},
		Session: &introspectSession{
			ID:                 sess.ID,
			DeviceID:           sess.DeviceID,
			ExpiresAt:          sess.ExpiresAt.UTC().Format(time.RFC3339),
			IdleExpiresAt:      sess.IdleExpiresAt.UTC().Format(time.RFC3339),
			LastSeenAt:         sess.LastSeenAt.UTC().Format(time.RFC3339),
			AuthMethod:         sess.AuthMethod,
			RiskScore:          sess.RiskScore,
			DeviceTrustLevel:   sess.DeviceTrustLevel,
			DeviceClientFamily: sess.DeviceClientFamily,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func hasIntrospectionClientMetadata(r *http.Request) bool {
	return strings.TrimSpace(r.Header.Get("X-Auth-Client-IP")) != ""
}

func introspectionClientIP(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Auth-Client-IP"))
}

func introspectionUserAgent(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Auth-Client-User-Agent"))
}

func introspectionClientFamily(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Auth-Client-Family"))
}
