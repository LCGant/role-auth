package handlers

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/LCGant/role-auth/internal/config"
)

// clientIP resolves client IP from X-Forwarded-For using a trusted-proxy chain model.
// It walks from right to left and returns the first untrusted hop.
func clientIP(r *http.Request, cfg config.Config) string {
	remoteHost := remoteAddrHost(r.RemoteAddr)
	if cfg.HTTP.TrustProxyHeader && proxyTrusted(remoteHost, cfg.HTTP.ProxyTrustedCIDRs) {
		return resolveForwardedClientIP(r.Header.Get("X-Forwarded-For"), remoteHost, cfg.HTTP.ProxyTrustedCIDRs)
	}
	return remoteHost
}

func parseForwardedFor(header string) []string {
	if header == "" {
		return nil
	}
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		ip := strings.TrimSpace(p)
		if ip == "" {
			continue
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			out = append(out, addr.String())
		}
	}
	return out
}

func resolveForwardedClientIP(header, remote string, allowed []netip.Prefix) string {
	remoteAddr, err := netip.ParseAddr(remote)
	if err != nil {
		return remote
	}
	if !prefixContains(allowed, remoteAddr) {
		return remote
	}
	hops := parseForwardedFor(header)
	hops = append(hops, remote)
	for i := len(hops) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(hops[i])
		if err != nil {
			continue
		}
		if prefixContains(allowed, addr) {
			continue
		}
		return addr.String()
	}
	return remote
}

func proxyTrusted(remote string, allowed []netip.Prefix) bool {
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		return false
	}
	return prefixContains(allowed, addr)
}

func prefixContains(allowed []netip.Prefix, addr netip.Addr) bool {
	for _, p := range allowed {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddrHost(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil && host != "" {
		return host
	}
	trimmed := strings.Trim(remoteAddr, "[]")
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		return addr.String()
	}
	return remoteAddr
}
