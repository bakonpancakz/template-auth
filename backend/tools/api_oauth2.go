package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

type OAuth2ErrorEnum string
type OAuth2ErrorDesc string

type ScopeInfo struct {
	Name string
	Flag int
}

const (
	GRANT_CODE    = "authorization_code"
	GRANT_REFRESH = "refresh_token"

	// Descriptions taken from document:
	// 	https://datatracker.ietf.org/doc/html/rfc6749#section-5.2

	// The request is missing a required parameter, includes an
	// unsupported parameter value (other than grant type),
	// repeats a parameter, includes multiple credentials,
	// utilizes more than one mechanism for authenticating the
	// client, or is otherwise malformed.
	INVALID_REQUEST OAuth2ErrorEnum = "invalid_request"

	// Client authentication failed (e.g., unknown client, no
	// client authentication included, or unsupported
	// authentication method).  The authorization server MAY
	// return an HTTP 401 (Unauthorized) status code to indicate
	// which HTTP authentication schemes are supported.  If the
	// client attempted to authenticate via the "Authorization"
	// request header field, the authorization server MUST
	// respond with an HTTP 401 (Unauthorized) status code and
	// include the "WWW-Authenticate" response header field
	// matching the authentication scheme used by the client.
	INVALID_CLIENT OAuth2ErrorEnum = "invalid_client"

	// The provided authorization grant (e.g., authorization
	// code, resource owner credentials) or refresh token is
	// invalid, expired, revoked, does not match the redirection
	// URI used in the authorization request, or was issued to
	// another client.
	INVALID_GRANT OAuth2ErrorEnum = "invalid_grant"

	// The authenticated client is not authorized to use this
	// authorization grant type.
	UNAUTHORIZED_CLIENT OAuth2ErrorEnum = "unauthorized_client"

	// The authorization grant type is not supported by the
	// authorization server.
	UNSUPPORTED_GRANT_TYPE OAuth2ErrorEnum = "unsupported_grant_type"

	// The authorization server does not support obtaining an
	// authorization code using this method.
	UNSUPPORTED_RESPONSE_TYPE OAuth2ErrorEnum = "unsupported_response_type"

	// The requested scope is invalid, unknown, malformed, or
	// exceeds the scope granted by the resource owner.
	INVALID_SCOPE OAuth2ErrorEnum = "invalid_scope"
)

// Shared OAuth2 Error Descriptions
const (
	AUTH_INVALID              OAuth2ErrorDesc = "Invalid client credentials"
	AUTH_FAILED               OAuth2ErrorDesc = "Client authentication failed"
	AUTH_REVOKED              OAuth2ErrorDesc = "User revoked consent"
	SCOPE_DUPLICATE           OAuth2ErrorDesc = "Invalid 'scopes' parameter: duplicate scope"
	SCOPE_UNKNOWN             OAuth2ErrorDesc = "Invalid 'scopes' parameter: unknown scope"
	RESPONSE_TYPE_EXPECT_CODE OAuth2ErrorDesc = "Invalid 'response_type' parameter: expected 'code'"
	REDIRECT_INVALID          OAuth2ErrorDesc = "Invalid 'redirect_uri' parameter: malformed"
	REDIRECT_DISALLOWED       OAuth2ErrorDesc = "Invalid 'redirect_uri' parameter: not registered"
	REDIRECT_BAD_SCHEME       OAuth2ErrorDesc = "Invalid 'redirect_uri' parameter: disallowed scheme"
	REDIRECT_BAD_LENGTH       OAuth2ErrorDesc = "Invalid 'redirect_uri' parameter: too long"
	REDIRECT_HAS_FRAGMENT     OAuth2ErrorDesc = "Invalid 'redirect_uri' parameter: contains fragment"
	CLIENT_ID_INVALID         OAuth2ErrorDesc = "invalid 'client_id' parameter"
	GRANT_TYPE_UNSUPPORTED    OAuth2ErrorDesc = "invalid 'grant_type' parameter"
	CODE_INVALID              OAuth2ErrorDesc = "Invalid 'code' parameter"
	REFRESH_TOKEN_UNKNOWN     OAuth2ErrorDesc = "Invalid or expired refresh token"
	GRANT_UNKNOWN             OAuth2ErrorDesc = "invalid or expired grant"

	// Unique errors for routes that "loosely" follow the spec
	UNKNOWN_APPLICATION OAuth2ErrorDesc = "unknown application"
	UNKNOWN_USER        OAuth2ErrorDesc = "unknown user"
)

var (
	ErrOAuth2UnknownScope             = errors.New("unknown scope")
	ErrOAuth2DuplicateScope           = errors.New("duplicate scope")
	ErrOAuth2RedirectUnknown          = errors.New("redirect not allowed")
	ErrOAuth2RedirectMalformed        = errors.New("redirect malformed")
	ErrOauth2RedirectHasFragment      = errors.New("redirect cannot include fragment")
	ErrOAuth2RedirectTooLong          = errors.New("redirect uri too long")
	ErrOAuth2RedirectSchemeDisallowed = errors.New("scheme must be http or https")

	SCOPE_READ_IDENTIFY = ScopeInfo{Flag: 1 << 0, Name: "identify"}
	SCOPE_READ_EMAIL    = ScopeInfo{Flag: 1 << 1, Name: "email"}
	SCOPE_HASH          = map[string]ScopeInfo{
		SCOPE_READ_IDENTIFY.Name: SCOPE_READ_IDENTIFY,
		SCOPE_READ_EMAIL.Name:    SCOPE_READ_EMAIL,
	}
)

// Validate 'Authorization' Header, return early if false
func OAuth2ValidateRequestAuth(ctx context.Context, w http.ResponseWriter, r *http.Request) (bool, int64) {

	// Validate Client Input
	username, password, ok := r.BasicAuth()
	if !ok {
		SendOAuth2Error(w, r, INVALID_CLIENT, AUTH_INVALID)
		return false, 0
	}
	id, err := strconv.ParseInt(username, 10, 64)
	if err != nil {
		SendOAuth2Error(w, r, INVALID_REQUEST, AUTH_INVALID)
		return false, 0
	}
	if !CompareSignedString(password) {
		SendOAuth2Error(w, r, INVALID_CLIENT, AUTH_FAILED)
		return false, 0
	}

	// Compare Application Secret
	var secretHash string
	err = Database.
		QueryRow(ctx, "SELECT auth_secret FROM auth.applications WHERE id = $1", id).
		Scan(&secretHash)
	if errors.Is(err, pgx.ErrNoRows) {
		SendOAuth2Error(w, r, INVALID_CLIENT, AUTH_FAILED)
		return false, 0
	}
	if err != nil {
		SendServerError(w, r, err)
		return false, 0
	}
	if !CompareApplicationSecret(password, secretHash) {
		SendOAuth2Error(w, r, INVALID_CLIENT, AUTH_FAILED)
		return false, 0
	}

	return true, id
}

// Validate Scope String, return early if false
func OAuth2ValidateRequestScopes(w http.ResponseWriter, r *http.Request, scopes string) (bool, int) {
	requestedScopes, err := OAuth2StringToScopes(scopes)
	if err != nil {
		if errors.Is(err, ErrOAuth2DuplicateScope) {
			SendOAuth2Error(w, r, INVALID_REQUEST, SCOPE_DUPLICATE)
			return false, 0
		}
		if errors.Is(err, ErrOAuth2UnknownScope) {
			SendOAuth2Error(w, r, INVALID_REQUEST, SCOPE_UNKNOWN)
			return false, 0
		}
		SendServerError(w, r, fmt.Errorf("unhandled error: %s", err.Error()))
		return false, 0
	}
	return true, requestedScopes
}

// Validate Redirect URI, return early if false
func OAuth2ValidateRedirectURI(w http.ResponseWriter, r *http.Request, redirect string) (bool, string) {
	uri, err := OAuth2RedirectCanonicalize(redirect)
	if err != nil {
		if errors.Is(err, ErrOAuth2RedirectTooLong) {
			SendOAuth2Error(w, r, INVALID_REQUEST, REDIRECT_BAD_LENGTH)
			return false, ""
		}
		if errors.Is(err, ErrOauth2RedirectHasFragment) {
			SendOAuth2Error(w, r, INVALID_REQUEST, REDIRECT_HAS_FRAGMENT)
			return false, ""
		}
		if errors.Is(err, ErrOAuth2RedirectSchemeDisallowed) {
			SendOAuth2Error(w, r, INVALID_REQUEST, REDIRECT_BAD_SCHEME)
			return false, ""
		}
		if errors.Is(err, ErrOAuth2RedirectMalformed) {
			SendOAuth2Error(w, r, INVALID_REQUEST, REDIRECT_INVALID)
			return false, ""
		}
		SendServerError(w, r, fmt.Errorf("unhandled error: %s", err.Error()))
		return false, ""
	}
	return true, uri
}

// Test for Given Scopes
func OAuth2ScopesContains(session *SessionData, scopes ...ScopeInfo) bool {
	if session.ApplicationID == SESSION_NO_APPLICATION_ID {
		// The User will always have full access to their account
		return true
	}
	// Find missing scope
	for _, s := range scopes {
		if (session.ConnectionScopes & s.Flag) == 0 {
			return false
		}
	}
	return true
}

// Convert oAuth2 Scopes into a String
func OAuth2ScopesToString(givenScopes int) string {
	scopes := make([]string, 0, len(SCOPE_HASH))
	for _, sc := range SCOPE_HASH {
		if (givenScopes & sc.Flag) != 0 {
			scopes = append(scopes, sc.Name)
		}
	}
	sort.Strings(scopes)
	return strings.Join(scopes, " ")
}

// Convert String into OAuth2 Scopes
func OAuth2StringToScopes(s string) (int, error) {
	scopes := strings.Fields(s)
	unique := make(map[string]struct{}, len(scopes))
	flags := 0
	for _, sc := range scopes {
		f, ok := SCOPE_HASH[sc]
		if !ok {
			// Prevent Unknown per standard
			return 0, ErrOAuth2UnknownScope
		}
		if _, ok := unique[sc]; ok {
			// Prevent Duplicates per standard
			return 0, ErrOAuth2DuplicateScope
		}
		unique[sc] = struct{}{}
		flags = flags | f.Flag
	}
	return flags, nil
}

// Compare Given URI to list of allowed URIs
//
// NOTE: Canonicalize the string with OAuth2RedirectCanonicalize() before calling!
func OAuth2RedirectCompare(standardString string, allowlist []string) (string, error) {
	for _, allowed := range allowlist {
		if standardString == allowed {
			return allowed, nil
		}
	}
	return "", ErrOAuth2RedirectUnknown
}

// Parse and Canonicalize the URI
func OAuth2RedirectCanonicalize(s string) (string, error) {

	// Additional Validation
	if len(s) > REDIRECT_URI_STRING_LEN_MAX {
		return "", ErrOAuth2RedirectTooLong
	}
	p, err := url.Parse(s)
	if err != nil {
		return "", ErrOAuth2RedirectMalformed
	}
	if p.Host == "" {
		return "", ErrOAuth2RedirectMalformed
	}
	if p.Fragment != "" {
		return "", ErrOauth2RedirectHasFragment
	}
	if p.Scheme != "https" && p.Scheme != "http" {
		return "", ErrOAuth2RedirectSchemeDisallowed
	}
	host := p.Hostname()
	port := p.Port()

	// Only allow http on localhost
	if p.Scheme == "http" && (host != "127.0.0.1" && host != "::1" && host != "localhost") {
		return "", ErrOAuth2RedirectSchemeDisallowed
	}
	// Remove Default Ports
	if p.Scheme == "http" && port == "80" {
		p.Host = host
	}
	if p.Scheme == "https" && port == "443" {
		p.Host = host
	}
	// Per standard
	if p.Path == "" {
		p.Path = "/"
	}

	// Skip Query String (if none given)
	uriScheme := strings.ToLower(p.Scheme)
	uriHost := strings.ToLower(p.Host)
	params := p.Query()
	if len(params) == 0 {
		return fmt.Sprintf("%s://%s%s", uriScheme, uriHost, p.Path), nil
	}

	// Sort Parameters
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build Query String
	var b strings.Builder
	b.WriteByte('?')
	first := true

	for _, k := range keys {
		for _, v := range params[k] {
			if !first {
				b.WriteByte('&')
			}
			first = false

			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}

	return fmt.Sprintf("%s://%s%s%s", uriScheme, uriHost, p.Path, b.String()), nil
}
