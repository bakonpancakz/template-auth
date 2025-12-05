package tests

import (
	"testing"

	"github.com/bakonpancakz/template-auth/include"
	"github.com/bakonpancakz/template-auth/tools"
)

type DatabaseResetOption struct {
	Query     string
	Arguments []any
}

// Reset Database to Original Schema
var RESET_BASE = DatabaseResetOption{
	Query:     include.DatabaseSchema,
	Arguments: []any{},
}

// Create Default Account with Default Profile
var RESET_ACCOUNT = DatabaseResetOption{
	Query:     `INSERT INTO auth.users (id, email_address, password_hash) VALUES ($1, $2, $3);`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_EMAIL_PRIMARY, TEST_PASSWORD_PRIMARY_HASH},
}

// With Verify Login, Verify Email, and Passcode Tokens
var RESET_ACCOUNT_TOKENS = DatabaseResetOption{
	Query:     `UPDATE auth.users SET token_verify = $1, token_verify_eat = $2, token_login = $3, token_login_data = $4, token_login_eat = $5, token_reset = $6, token_reset_eat = $7 WHERE id = $8`,
	Arguments: []any{TEST_TOKEN_PRIMARY, TEST_TOKEN_EXPIRES_FUTURE, TEST_TOKEN_PRIMARY, TEST_IP_ADDRESS, TEST_TOKEN_EXPIRES_FUTURE, TEST_TOKEN_PRIMARY, TEST_TOKEN_EXPIRES_FUTURE, TEST_ID_PRIMARY},
}

// With MFA Fields
var RESET_ACCOUNT_MFA = DatabaseResetOption{
	Query:     `UPDATE auth.users SET mfa_enabled = TRUE, mfa_secret = $1, mfa_codes = $2 WHERE id = $3`,
	Arguments: []any{TEST_TOTP_SECRET, TEST_TOTP_RECOVERY_CODES, TEST_ID_PRIMARY},
}

// With Default Profile
var RESET_PROFILE = DatabaseResetOption{
	Query:     `INSERT INTO auth.profiles (id, username, displayname) VALUES ($1, $2, $3);`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_USERNAME_PRIMARY, TEST_DISPLAYNAME_PRIMARY},
}

// Personalize Default Profile
var RESET_PROFILE_CUSTOMIZED = DatabaseResetOption{
	Query:     `UPDATE auth.profiles SET displayname = $1, subtitle = $2, biography = $3, avatar_hash = $4, banner_hash = $5, accent_banner = $6, accent_border = $7, accent_background = $8 WHERE id = $9`,
	Arguments: []any{TEST_DISPLAYNAME_PRIMARY, TEST_SUBTITLE_PRIMARY, TEST_BIOGRAPHY_PRIMARY, TEST_HASH_PRIMARY, TEST_HASH_PRIMARY, TEST_COLOR_PRIMARY, TEST_COLOR_PRIMARY, TEST_COLOR_PRIMARY, TEST_ID_PRIMARY},
}

// Create Default Session
var RESET_SESSION = DatabaseResetOption{
	Query:     `INSERT INTO auth.sessions (id, user_id, token, device_ip_address, device_user_agent) VALUES ($1, $2, $3, $4, $5)`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_ID_PRIMARY, TEST_TOKEN_PRIMARY, TEST_IP_ADDRESS, TEST_IP_AGENT},
}

// Update Default Session as Revoked
var RESET_SESSION_REVOKED = DatabaseResetOption{
	Query:     `UPDATE auth.sessions SET revoked = TRUE WHERE id = $1 AND user_id = $2`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_ID_PRIMARY},
}

// Update Default Session as Elevated
var RESET_SESSION_ELEVATED = DatabaseResetOption{
	Query:     `UPDATE auth.sessions SET elevated_until = $1 WHERE id = $2 AND user_id = $3`,
	Arguments: []any{TEST_TOKEN_EXPIRES_FUTURE.Unix(), TEST_ID_PRIMARY, TEST_ID_PRIMARY},
}

// Create Default Application
var RESET_APPLICATION = DatabaseResetOption{
	Query:     `INSERT INTO auth.applications (id, user_id, name, auth_secret) VALUES ($1, $2, $3, $4)`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_ID_PRIMARY, TEST_DISPLAYNAME_PRIMARY, TEST_OAUTH2_SECRET_HASH},
}

// Personalize Default Application
var RESET_APPLICATION_CUSTOMIZED = DatabaseResetOption{
	Query:     `UPDATE auth.applications SET description = $1, icon_hash = $2, auth_redirects = $3 WHERE id = $4 AND user_id = $5`,
	Arguments: []any{TEST_BIOGRAPHY_PRIMARY, TEST_HASH_PRIMARY, TEST_REDIRECT_PRIMARY, TEST_ID_PRIMARY, TEST_ID_PRIMARY},
}

// Create Default Connection for Default Application
var RESET_CONNECTION = DatabaseResetOption{
	Query:     `INSERT INTO auth.connections (id, user_id, application_id, scopes, token_access, token_expires, token_refresh) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_ID_PRIMARY, TEST_ID_PRIMARY, TEST_OAUTH2_SCOPE_INTEGER, TEST_TOKEN_PRIMARY, TEST_TOKEN_EXPIRES_FUTURE, TEST_TOKEN_SECONDARY},
}

// Create Default Grant for Default Application
var RESET_GRANT = DatabaseResetOption{
	Query:     `INSERT INTO auth.grants (id, expires, user_id, application_id, redirect_uri, scopes, code) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_TOKEN_EXPIRES_FUTURE, TEST_ID_PRIMARY, TEST_ID_PRIMARY, TEST_REDIRECT_URI_PRIMARY, TEST_OAUTH2_SCOPE_INTEGER, TEST_TOKEN_PRIMARY},
}

// With OAuth2 Scope 'identify'
var RESET_CONNECTION_SCOPE_READ_IDENTIFY = DatabaseResetOption{
	Query:     "UPDATE auth.connections SET scopes = scopes | $1 WHERE id = $2",
	Arguments: []any{tools.SCOPE_READ_IDENTIFY.Flag, TEST_ID_PRIMARY},
}

// With OAuth2 Scope 'email'
var RESET_CONNECTION_SCOPE_READ_EMAIL = DatabaseResetOption{
	Query:     "UPDATE auth.connections SET scopes = scopes | $1 WHERE id = $2",
	Arguments: []any{tools.SCOPE_READ_EMAIL.Flag, TEST_ID_PRIMARY},
}

// Update Default Connection as Revoked
var RESET_CONNECTION_REVOKED = DatabaseResetOption{
	Query:     `UPDATE auth.connections SET revoked = FALSE, scopes  = 0 WHERE id = $1 AND user_id = $2`,
	Arguments: []any{TEST_ID_PRIMARY, TEST_ID_PRIMARY},
}

// Reset the Database to the Default Schema, applys dummy data if flags specify
func ResetDatabase(t *testing.T, options ...DatabaseResetOption) {
	for _, o := range options {
		_, err := tools.Database.Exec(t.Context(), o.Query, o.Arguments...)
		if err != nil {
			panic(err)
		}
	}
}

// Execute SQL on the Database, errors if no rows were affected or execution fails
func ExecDatabase(t *testing.T, query string, args ...any) {
	tag, err := tools.Database.Exec(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("database exec failed: %s", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatalf("database exec affected zero rows")
	}
}

// Search Database for Rows, errors if no rows match or execution fails
func QueryDatabaseRow(t *testing.T, query string, args []any, scan ...any) {
	err := tools.Database.
		QueryRow(t.Context(), query, args...).
		Scan(scan...)
	if err != nil {
		t.Fatalf("database query failed: %s", err)
	}
}
