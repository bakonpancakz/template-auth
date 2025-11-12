package tests

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bakonpancakz/template-auth/tools"
)

func Test_Login_Endpoints(t *testing.T) {

	t.Run("/auth/signup", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_PROFILE)

		t.Run("Invalid Username", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_INVALID,
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_BODY_INVALID_FIELD.Status).
				ExpectInteger("code", int64(tools.ERROR_BODY_INVALID_FIELD.Code))
		})

		t.Run("Invalid Email Address", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_PRIMARY,
					"email":    TEST_EMAIL_INVALID,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_BODY_INVALID_FIELD.Status).
				ExpectInteger("code", int64(tools.ERROR_BODY_INVALID_FIELD.Code))
		})

		t.Run("Invalid Password", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_PRIMARY,
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_INVALID,
				}).
				Send().
				ExpectStatus(tools.ERROR_BODY_INVALID_FIELD.Status).
				ExpectInteger("code", int64(tools.ERROR_BODY_INVALID_FIELD.Code))
		})

		t.Run("Signup - Duplicate Email", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_SECONDARY,
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_SIGNUP_DUPLICATE_EMAIL.Status).
				ExpectInteger("code", int64(tools.ERROR_SIGNUP_DUPLICATE_EMAIL.Code))
		})

		t.Run("Signup - Duplicate Username", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_PRIMARY,
					"email":    TEST_EMAIL_SECONDARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_SIGNUP_DUPLICATE_USERNAME.Status).
				ExpectInteger("code", int64(tools.ERROR_SIGNUP_DUPLICATE_USERNAME.Code))
		})

		t.Run("Signup Normally", func(t *testing.T) {
			ResetDatabase(t, RESET_BASE)
			NewTestRequest(t, "POST", "/auth/signup").
				WithJSON(map[string]any{
					"username": TEST_USERNAME_PRIMARY,
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusNoContent)
		})
	})

	t.Run("/auth/login", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT)

		t.Run("MFA Challenge - New Location", func(t *testing.T) {
			ExecDatabase(t,
				`UPDATE auth.users SET ip_address = '', email_verified = TRUE WHERE id = $1`,
				TEST_ID_PRIMARY,
			)
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_MFA_EMAIL_SENT.Status).
				ExpectInteger("code", int64(tools.ERROR_MFA_EMAIL_SENT.Code))

			// Ensure Fields are Present
			var stateToken, stateData *string
			var stateExpired *time.Time
			QueryDatabaseRow(t,
				"SELECT token_login, token_login_data, token_login_eat FROM auth.users WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateToken, &stateData, &stateExpired,
			)
			if stateToken == nil || stateData == nil || stateExpired == nil {
				t.Errorf("some token_login field is empty")
			}
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_ACCOUNT_MFA)

		t.Run("MFA Challenge - TOTP: Prompt Passcode", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_MFA_PASSCODE_REQUIRED.Status).
				ExpectInteger("code", int64(tools.ERROR_MFA_PASSCODE_REQUIRED.Code))
		})

		t.Run("MFA Challenge - TOTP: Recovery Code (Incorrect)", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
					"passcode": TEST_TOTP_RECOVERY_CODE_INVALID,
				}).
				Send().
				ExpectStatus(tools.ERROR_MFA_RECOVERY_CODE_INCORRECT.Status).
				ExpectInteger("code", int64(tools.ERROR_MFA_RECOVERY_CODE_INCORRECT.Code))
		})

		t.Run("MFA Challenge - TOTP: Recovery Code", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
					"passcode": TEST_TOTP_RECOVERY_CODES[0],
				}).
				Send().
				ExpectStatus(http.StatusNoContent).
				ExpectCookie(tools.HTTP_COOKIE_NAME)
		})

		t.Run("MFA Challenge - TOTP: Use Passcode (Incorrect)", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
					"passcode": TEST_TOTP_PASSCODE_INVALID,
				}).
				Send().
				ExpectStatus(tools.ERROR_MFA_PASSCODE_INCORRECT.Status).
				ExpectInteger("code", int64(tools.ERROR_MFA_PASSCODE_INCORRECT.Code))
		})

		t.Run("MFA Challenge - TOTP: Use Passcode", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
					"passcode": tools.GenerateTOTPCode(TEST_TOTP_SECRET, time.Now()),
				}).
				Send().
				ExpectStatus(http.StatusNoContent).
				ExpectCookie(tools.HTTP_COOKIE_NAME)
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT)

		t.Run("Incorrect Login - NULL Password", func(t *testing.T) {
			ExecDatabase(t,
				`UPDATE auth.users SET password_hash = NULL WHERE id = $1`,
				TEST_ID_PRIMARY,
			)
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_LOGIN_PASSWORD_RESET.Status).
				ExpectInteger("code", int64(tools.ERROR_LOGIN_PASSWORD_RESET.Code))
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT)

		t.Run("Incorrect Login - Incorrect Password", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_SECONDARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_LOGIN_INCORRECT.Status).
				ExpectInteger("code", int64(tools.ERROR_LOGIN_INCORRECT.Code))
		})

		t.Run("Incorrect Login - Incorrect Email Address", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_SECONDARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_LOGIN_INCORRECT.Status).
				ExpectInteger("code", int64(tools.ERROR_LOGIN_INCORRECT.Code))
		})

		t.Run("Login Normally", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/login").
				WithJSON(map[string]any{
					"email":    TEST_EMAIL_PRIMARY,
					"password": TEST_PASSWORD_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusNoContent).
				ExpectCookie(tools.HTTP_COOKIE_NAME)
		})

	})

	t.Run("/auth/logout", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_SESSION)

		t.Run("Logout - No Session", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/logout").
				Send().
				ExpectStatus(tools.ERROR_GENERIC_UNAUTHORIZED.Status).
				ExpectInteger("code", int64(tools.ERROR_GENERIC_UNAUTHORIZED.Code))
		})

		t.Run("Logout - Normally", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/logout").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(http.StatusNoContent).
				ExpectCookie(tools.HTTP_COOKIE_NAME)
		})

		t.Run("Logout - Revoked Session", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/logout").
				Send().
				ExpectStatus(tools.ERROR_GENERIC_UNAUTHORIZED.Status).
				ExpectInteger("code", int64(tools.ERROR_GENERIC_UNAUTHORIZED.Code))
		})
	})

	t.Run("/auth/password-reset", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT)
		var stateToken *string

		t.Run("POST: Request Password Reset", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/password-reset").
				WithJSON(map[string]any{
					"email": TEST_EMAIL_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusNoContent)

			QueryDatabaseRow(t, "SELECT token_reset FROM auth.users WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateToken,
			)
			if stateToken == nil {
				t.Errorf("reset token was not set")
			}
		})

		t.Run("PATCH: Update Password using Token", func(t *testing.T) {
			NewTestRequest(t, "PATCH", "/auth/password-reset").
				WithJSON(map[string]any{
					"password": TEST_PASSWORD_PRIMARY,
					"token":    stateToken,
				}).
				Send().
				ExpectStatus(http.StatusNoContent)

			QueryDatabaseRow(t, "SELECT token_reset FROM auth.users WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateToken,
			)
			if stateToken != nil {
				t.Errorf("reset token was not cleared")
			}
		})
	})

	t.Run("/auth/verify-login", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_ACCOUNT_TOKENS)

		t.Run("Use Invalid Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-login").
				WithQuery(map[string]any{
					"token": TEST_TOKEN_INVALID,
				}).
				Send().
				ExpectStatus(tools.ERROR_BODY_INVALID_FIELD.Status).
				ExpectInteger("code", int64(tools.ERROR_BODY_INVALID_FIELD.Code))
		})

		t.Run("Use Incorrect Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-login").
				WithQuery(map[string]any{
					"token": TEST_TOKEN_SECONDARY,
				}).
				Send().
				ExpectStatus(tools.ERROR_UNKNOWN_TOKEN.Status).
				ExpectInteger("code", int64(tools.ERROR_UNKNOWN_TOKEN.Code))
		})

		t.Run("Use Correct Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-login").
				WithQuery(map[string]any{
					"token": TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusNoContent)

			var stateAddress string
			QueryDatabaseRow(t, "SELECT ip_address FROM auth.users WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateAddress,
			)
			if !strings.EqualFold(stateAddress, TEST_IP_ADDRESS) {
				t.Errorf("ip address is incorrect: got %s, want %s", stateAddress, TEST_IP_ADDRESS)
			}
		})
	})

	t.Run("/auth/verify-email", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_ACCOUNT_TOKENS)

		t.Run("Use Invalid Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-email").
				WithQuery(map[string]any{"token": TEST_TOKEN_INVALID}).
				Send().
				ExpectStatus(tools.ERROR_BODY_INVALID_FIELD.Status).
				ExpectInteger("code", int64(tools.ERROR_BODY_INVALID_FIELD.Code))
		})

		t.Run("Use Incorrect Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-email").
				WithQuery(map[string]any{"token": TEST_TOKEN_SECONDARY}).
				Send().
				ExpectStatus(tools.ERROR_UNKNOWN_TOKEN.Status).
				ExpectInteger("code", int64(tools.ERROR_UNKNOWN_TOKEN.Code))
		})

		t.Run("Use Correct Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/auth/verify-email").
				WithQuery(map[string]any{"token": TEST_TOKEN_PRIMARY}).
				Send().
				ExpectStatus(http.StatusNoContent)

			var stateVerified bool
			QueryDatabaseRow(t, "SELECT email_verified FROM auth.users WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateVerified,
			)
			if !stateVerified {
				t.Errorf("email address was not verified")
			}
		})
	})

}
