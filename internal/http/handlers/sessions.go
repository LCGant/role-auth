package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/LCGant/role-auth/internal/store"
)

func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sessions, err := s.auth.ListSessions(r.Context(), authUser.User.ID)
	if err != nil {
		http.Error(w, "cannot list sessions", http.StatusInternalServerError)
		return
	}
	resp := make([]map[string]any, 0, len(sessions))
	for _, sess := range sessions {
		resp = append(resp, serializeSession(sess, authUser.Session))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": resp})
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	devices, err := s.auth.ListDevices(r.Context(), authUser.User.ID)
	if err != nil {
		http.Error(w, "cannot list devices", http.StatusInternalServerError)
		return
	}
	resp := make([]map[string]any, 0, len(devices))
	for _, device := range devices {
		resp = append(resp, serializeDevice(device, authUser.Session))
	}
	writeJSON(w, http.StatusOK, map[string]any{"devices": resp})
}

func (s *Server) handleRevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
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
	if err := s.auth.RevokeOtherSessions(r.Context(), authUser.User.ID, authUser.Session.TokenHash); err != nil {
		http.Error(w, "cannot revoke sessions", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": "others"})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	sessionID, ok := parsePathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	if authUser.Session.ID != sessionID {
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
	}
	if err := s.auth.RevokeSession(r.Context(), authUser.User.ID, sessionID); err != nil {
		http.Error(w, "cannot revoke session", http.StatusInternalServerError)
		return
	}
	if authUser.Session.ID == sessionID {
		clearSessionCookie(w, s.cfg)
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked_session_id": sessionID})
}

func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	authUser, ok := s.requireUser(w, r)
	if !ok {
		return
	}
	deviceID, ok := parsePathID(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
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
	if err := s.auth.RevokeDevice(r.Context(), authUser.User.ID, deviceID); err != nil {
		http.Error(w, "cannot revoke device", http.StatusInternalServerError)
		return
	}
	if authUser.Session.DeviceID == deviceID {
		clearSessionCookie(w, s.cfg)
		clearDeviceCookie(w, s.cfg)
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked_device_id": deviceID})
}

func serializeSession(sess *store.Session, current *store.Session) map[string]any {
	return map[string]any{
		"id":                   sess.ID,
		"device_id":            sess.DeviceID,
		"aal":                  sess.AAL,
		"auth_method":          sess.AuthMethod,
		"risk_score":           sess.RiskScore,
		"device_trust_level":   strings.TrimSpace(sess.DeviceTrustLevel),
		"device_client_family": strings.TrimSpace(sess.DeviceClientFamily),
		"expires_at":           sess.ExpiresAt.UTC().Format(http.TimeFormat),
		"idle_expires_at":      sess.IdleExpiresAt.UTC().Format(http.TimeFormat),
		"auth_time":            sess.AuthTime.UTC().Format(http.TimeFormat),
		"created_at":           sess.CreatedAt.UTC().Format(http.TimeFormat),
		"last_seen_at":         sess.LastSeenAt.UTC().Format(http.TimeFormat),
		"ip":                   sess.IP,
		"user_agent":           sess.UserAgent,
		"current":              current != nil && current.ID == sess.ID,
	}
}

func serializeDevice(device *store.Device, current *store.Session) map[string]any {
	return map[string]any{
		"id":              device.ID,
		"client_family":   device.ClientFamily,
		"trust_level":     device.TrustLevel,
		"risk_score":      device.RiskScore,
		"first_seen_at":   device.FirstSeenAt.UTC().Format(http.TimeFormat),
		"last_seen_at":    device.LastSeenAt.UTC().Format(http.TimeFormat),
		"last_ip":         device.LastIP,
		"last_user_agent": device.LastUserAgent,
		"current":         current != nil && current.DeviceID == device.ID,
	}
}

func parsePathID(raw string) (int64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		return 0, false
	}
	return id, true
}
