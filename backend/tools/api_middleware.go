package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ID Reserved for when Session belongs to a User
const SESSION_NO_APPLICATION_ID = 0

type SessionData struct {
	UserID           int64 // Relevant User ID
	SessionID        int64 // Relevant Session ID
	ConnectionID     int64 // Relevant Connection ID
	ConnectionScopes int   // Relevant Connection Scopes (APP_USER for User)
	ApplicationID    int64 // Relevant Application ID (APP_USER for User)
	Elevated         bool  // Relevant Session Elevated?
}

type RatelimitOptions struct {
	Bucket string        // Bucket Name
	Period time.Duration // Reset Period
	Limit  int64         // Maximum Amount of Requests
}

// Append Branding to Request :3
func UseServer(w http.ResponseWriter, r *http.Request) bool {
	if HTTP_SERVER_TOKEN {
		w.Header().Set("Server", "template-auth (bakonpancakz)")
	}
	return true
}

// Protect Server against Abuse by Limiting the amount of incoming bytes
func NewBodyLimit(limit int64) MiddlewareFunc {
	return func(w http.ResponseWriter, r *http.Request) bool {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if r.ContentLength > limit {
			SendClientError(w, r, ERROR_BODY_TOO_LARGE)
			return false
		}
		return true
	}
}

// Apply CORS Headers to Applicable requests
func UseCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, allowed := range HTTP_CORS_ORIGINS {
		if origin == allowed {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowed)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusOK)
				return false
			}
			return true
		}
	}
	w.WriteHeader(http.StatusForbidden)
	return false
}

// Protect Server against Abuse by Limiting the amount of incoming requests
func NewRatelimit(o *RatelimitOptions) MiddlewareFunc {
	return func(w http.ResponseWriter, r *http.Request) bool {
		// Generate Key
		keyData := fmt.Sprint(o.Bucket, r.Method, r.URL.String(), GetRemoteIP(r))
		KeySHAd := sha256.Sum256([]byte(keyData))
		keyHash := hex.EncodeToString(KeySHAd[:])

		// Fetch Limit
		ctx, cancel := NewContext()
		defer cancel()

		usage, err := Ratelimit.Increment(ctx, keyHash, o.Period)
		if err != nil {
			SendServerError(w, r, err)
			return false
		}
		ttl, err := Ratelimit.TTL(ctx, keyHash)
		if err != nil {
			SendServerError(w, r, err)
			return false
		}

		// Apply Headers
		remain := o.Limit - usage
		if remain < 0 {
			remain = 0
		}
		h := w.Header()
		h.Set("X-Ratelimit-Limit", strconv.FormatInt(o.Limit, 10))
		h.Set("X-Ratelimit-Remaining", strconv.FormatInt(remain, 10))
		h.Set("X-Ratelimit-Reset", strconv.FormatFloat(ttl.Seconds(), 'f', 2, 64))

		// Apply Limit
		if usage > o.Limit {
			SendClientError(w, r, ERROR_GENERIC_RATELIMIT)
			return false
		}

		return true
	}
}

// Retrieve User or Application Session from Request
func UseSession(w http.ResponseWriter, r *http.Request) bool {

	// Determine Lookup Type and Token
	var givenApplication bool
	var givenToken string

	cookie, err := r.Cookie(HTTP_COOKIE_NAME)
	switch {

	// Check Authorization Header
	case errors.Is(err, http.ErrNoCookie):
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		switch {
		case strings.HasPrefix(h, TOKEN_PREFIX_USER):
			// Authenticate as User using Header
			givenApplication = false
			givenToken = h[len(TOKEN_PREFIX_USER):]

		case strings.HasPrefix(h, TOKEN_PREFIX_BEARER):
			// Authenticate as Application using Header
			givenApplication = true
			givenToken = h[len(TOKEN_PREFIX_BEARER):]

		default:
			// Unsupported Prefix
			SendClientError(w, r, ERROR_GENERIC_UNAUTHORIZED)
			return false
		}

	// Authenticate as User using Cookie
	case err == nil:
		givenApplication = false
		givenToken = cookie.Value

		// Invalid or Malformed Cookie
	default:
		SendClientError(w, r, ERROR_GENERIC_UNAUTHORIZED)
		return false
	}

	ctx, cancel := NewContext()
	defer cancel()

	// Lookup Session via Token
	var session SessionData
	if givenApplication {

		// Search Connections
		var connectionExpires time.Time
		var connectionRevoked bool
		err := Database.QueryRow(ctx,
			`SELECT
				id, user_id, application_id, revoked, scopes, token_expires
			FROM auth.connections
			WHERE token_access = $1`,
			givenToken,
		).Scan(
			&session.ConnectionID,
			&session.UserID,
			&session.ApplicationID,
			&connectionRevoked,
			&session.ConnectionScopes,
			&connectionExpires,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			SendClientError(w, r, ERROR_GENERIC_UNAUTHORIZED)
			return false
		}
		if err != nil {
			SendServerError(w, r, err)
			return false
		}

		// Additional Validation
		if time.Now().After(connectionExpires) {
			SendClientError(w, r, ERROR_ACCESS_EXPIRED)
			return false
		}
		if connectionRevoked {
			SendClientError(w, r, ERROR_ACCESS_REVOKED)
			return false
		}

	} else {

		// Search Sessions
		var sessionRevoked bool
		var sessionElevatedUntil int64

		err := Database.QueryRow(ctx,
			`SELECT
				id, user_id, revoked, elevated_until
			FROM auth.sessions
			WHERE token = $1`,
			givenToken,
		).Scan(
			&session.SessionID, &session.UserID,
			&sessionRevoked, &sessionElevatedUntil,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			SendClientError(w, r, ERROR_GENERIC_UNAUTHORIZED)
			return false
		}
		if err != nil {
			SendServerError(w, r, err)
			return false
		}

		// Additional Validation
		if sessionRevoked {
			SendClientError(w, r, ERROR_ACCESS_REVOKED)
			return false
		}
		if sessionElevatedUntil > time.Now().Unix() {
			session.Elevated = true
		}
		session.ApplicationID = SESSION_NO_APPLICATION_ID
	}

	// Apply Session to Request Context
	ctxWithSession := context.WithValue(r.Context(), SESSION_KEY, &session)
	*r = *r.WithContext(ctxWithSession)
	return true
}
