package api

import (
	"net"
	"net/http"
	"strings"
	"argus/config"
)

// IP + Token Auth Middleware
func WithAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		clientIP := net.ParseIP(ip)

		if !isAllowedIP(clientIP) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Αν δεν υπάρχουν tokens, άσε το request να περάσει
		if len(config.AppConfig.API.Tokens) == 0 {
			handler(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if !isValidToken(token) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		handler(w, r)
	}
}

func isAllowedIP(ip net.IP) bool {
	for _, entry := range config.AppConfig.API.AllowIPs {
		// CIDR support
		if strings.Contains(entry, "/") {
			if _, cidrNet, err := net.ParseCIDR(entry); err == nil {
				if cidrNet.Contains(ip) {
					return true
				}
			}
		} else {
			if ip.Equal(net.ParseIP(entry)) {
				return true
			}
		}
	}
	return false
}

func isValidToken(token string) bool {
	for _, t := range config.AppConfig.API.Tokens {
		if token == t {
			return true
		}
	}
	return false
}
