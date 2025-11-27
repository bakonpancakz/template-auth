package tools

import (
	"net"
	"net/http"
	"strconv"
	"strings"
)

// Fetch Session from Request Context.
// Expects UseSession to be present in the http handler chain otherwise it panics
func GetSession(r *http.Request) *SessionData {
	v := r.Context().Value(SESSION_KEY)
	if v == nil {
		panic("missing session in request context; this request should have returned earlier")
	}
	return v.(*SessionData)
}

// Get Snowflake from Request Path.
// Expects id to be present in http handler (e.g. '/path/to/item/{id}')
func GetSnowflake(w http.ResponseWriter, r *http.Request) (bool, int64) {
	v, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		sendFormError(w, r, ValidationError{
			Field: "id",
			Error: VALIDATOR_STRING_NOT_A_NUMBER,
		})
		return false, 0
	}
	if v < 1 {
		sendFormError(w, r, ValidationError{
			Field:    "id",
			Error:    VALIDATOR_INTEGER_TOO_SMALL,
			Literals: []any{1},
		})
		return false, 0
	}
	return true, v
}

// Get IP Address of Incoming Client
func GetRemoteIP(r *http.Request) string {
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	clientIP := net.ParseIP(remoteAddr)

	// Skip if request was not proxied
	if len(HTTP_IP_HEADERS) == 0 || len(HTTP_IP_PROXIES) == 0 {
		return clientIP.String()
	}

	// Walk through headers in configured order (most recent first)
	// Scan Headers as Configured by Environment
	for _, header := range HTTP_IP_HEADERS {
		hv := r.Header.Get(header)
		if hv == "" {
			continue
		}
		for _, ipStr := range strings.Split(hv, ",") {
			ipStr = strings.TrimSpace(ipStr)
			ip := net.ParseIP(ipStr)
			if ip != nil && !isTrustedProxy(ip) {
				return ip.String()
			}
		}
	}

	// Proxy is misconfigured, use fallback!
	return clientIP.String()
}

func isTrustedProxy(ip net.IP) bool {
	for _, cidr := range HTTP_IP_PROXIES {
		if _, network, err := net.ParseCIDR(cidr); err == nil {
			if network.Contains(ip) {
				return true
			}
		} else if proxyIP := net.ParseIP(cidr); proxyIP != nil && proxyIP.Equal(ip) {
			return true
		}
	}
	return false
}
