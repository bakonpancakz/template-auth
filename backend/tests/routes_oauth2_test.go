package tests

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/bakonpancakz/template-auth/tools"
)

func Test_oAuth2_Endpoints(t *testing.T) {

	t.Run("/oauth2/authorize", func(t *testing.T) {
		ResetDatabase(t,
			RESET_BASE,
			RESET_ACCOUNT, RESET_PROFILE, RESET_SESSION,
			RESET_APPLICATION, RESET_APPLICATION_CUSTOMIZED,
		)

		t.Run("GET: User and Application - Incorrect Client ID", func(t *testing.T) {
			NewTestRequest(t, "GET", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_SECONDARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_REQUEST)).
				ExpectString("error_description", string(tools.UNKNOWN_APPLICATION))
		})

		t.Run("GET: User and Application - Incorrect Response Type", func(t *testing.T) {
			NewTestRequest(t, "GET", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "nacho",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.UNSUPPORTED_RESPONSE_TYPE)).
				ExpectString("error_description", string(tools.RESPONSE_TYPE_EXPECT_CODE))
		})

		t.Run("GET: User and Application - Incorrect Scopes", func(t *testing.T) {
			NewTestRequest(t, "GET", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING_INVALID,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_REQUEST)).
				ExpectString("error_description", string(tools.SCOPE_UNKNOWN))
		})

		t.Run("GET: User and Application", func(t *testing.T) {
			NewTestRequest(t, "GET", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"state":         TEST_OAUTH2_STATE_STRING,
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusOK).
				ExpectString("redirect", TEST_REDIRECT_URI_PRIMARY).
				ExpectInteger("scopes", int64(TEST_OAUTH2_SCOPE_INTEGER)).
				ExpectString("state", TEST_OAUTH2_STATE_STRING).
				ExpectField("application").
				ExpectField("user")
		})

		t.Run("POST: Create Grant - Incorrect Client ID", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_SECONDARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusUnauthorized).
				ExpectString("error", string(tools.INVALID_CLIENT)).
				ExpectString("error_description", string(tools.UNKNOWN_APPLICATION))
		})

		t.Run("POST: Create Grant - Incorrect Response Type", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "nacho",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.UNSUPPORTED_RESPONSE_TYPE)).
				ExpectString("error_description", string(tools.RESPONSE_TYPE_EXPECT_CODE))
		})

		t.Run("POST: Create Grant - Incorrect Scopes", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING_INVALID,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_REQUEST)).
				ExpectString("error_description", string(tools.SCOPE_UNKNOWN))
		})

		t.Run("POST: Create Grant", func(t *testing.T) {
			resp := NewTestRequest(t, "POST", "/oauth2/authorize").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				WithQuery(map[string]any{
					"state":         TEST_OAUTH2_STATE_STRING,
					"client_id":     TEST_ID_PRIMARY,
					"response_type": "code",
					"redirect_uri":  TEST_REDIRECT_URI_PRIMARY,
					"scope":         TEST_OAUTH2_SCOPE_STRING,
				}).
				Send().
				ExpectStatus(http.StatusFound)

			// Validate Redirect
			header := resp.response.Header.Get("Location")
			url, err := url.Parse(header)
			if err != nil {
				t.Fatalf("invalid location header: %s", header)
			}
			query := url.Query()
			state := query.Get("state")
			if !query.Has("code") {
				t.Fatal("redirect uri did not include a code")
			}
			if state != TEST_OAUTH2_STATE_STRING {
				t.Fatalf("redirect uri includes incorrect state expected '%s' got '%s'",
					TEST_OAUTH2_STATE_STRING, state)
			}

		})

	})

	t.Run("/oauth2/token", func(t *testing.T) {
		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_GRANT)

		t.Run("Use Grant - Invalid Client ID", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_INVALID_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_PRIMARY,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusUnauthorized).
				ExpectString("error", string(tools.INVALID_CLIENT)).
				ExpectString("error_description", string(tools.AUTH_FAILED))
		})

		t.Run("Use Grant - Invalid Client Secret", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_INVALID).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_PRIMARY,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusUnauthorized).
				ExpectString("error", string(tools.INVALID_CLIENT)).
				ExpectString("error_description", string(tools.AUTH_FAILED))
		})

		t.Run("Use Grant - Invalid Redirect URI", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_INVALID,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_REQUEST)).
				ExpectString("error_description", string(tools.REDIRECT_INVALID))
		})

		t.Run("Use Grant - Unknown Redirect URI", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_SECONDARY,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_GRANT)).
				ExpectString("error_description", string(tools.GRANT_UNKNOWN))
		})

		t.Run("Use Grant - Invalid Code", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_PRIMARY,
					"code":         TEST_TOKEN_SECONDARY,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_GRANT)).
				ExpectString("error_description", string(tools.GRANT_UNKNOWN))
		})

		t.Run("Use Grant - New Connection", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_PRIMARY,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusOK).
				ExpectString("token_type", tools.TOKEN_PREFIX_BEARER).
				ExpectField("access_token").
				ExpectField("refresh_token").
				ExpectInteger("expires_in", int64(tools.LIFETIME_OAUTH2_ACCESS_TOKEN.Seconds())).
				ExpectString("scopes", TEST_OAUTH2_SCOPE_STRING)
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_CONNECTION, RESET_GRANT)

		t.Run("Use Grant - Existing Connection", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":   tools.GRANT_CODE,
					"redirect_uri": TEST_REDIRECT_URI_PRIMARY,
					"code":         TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusOK).
				ExpectString("token_type", tools.TOKEN_PREFIX_BEARER).
				ExpectField("access_token").
				ExpectField("refresh_token").
				ExpectInteger("expires_in", int64(tools.LIFETIME_OAUTH2_ACCESS_TOKEN.Seconds())).
				ExpectString("scopes", TEST_OAUTH2_SCOPE_STRING)

			var stateAccess, stateRefresh *string
			QueryDatabaseRow(t,
				"SELECT token_access, token_refresh FROM auth.connections WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateAccess, &stateRefresh,
			)
			if (stateAccess == nil || *stateAccess == TEST_TOKEN_PRIMARY) ||
				(stateRefresh == nil || *stateRefresh == TEST_TOKEN_PRIMARY) {
				t.Fatalf("tokens were not refreshed | previous: %s | access:%s | refresh: %s",
					TEST_TOKEN_PRIMARY, *stateAccess, *stateRefresh)
			}
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_CONNECTION, RESET_GRANT)

		t.Run("Refresh Grant - Invalid Refresh Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":    tools.GRANT_REFRESH,
					"refresh_token": TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusBadRequest).
				ExpectString("error", string(tools.INVALID_GRANT)).
				ExpectString("error_description", string(tools.REFRESH_TOKEN_UNKNOWN))
		})

		t.Run("Refresh Grant", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"grant_type":    tools.GRANT_REFRESH,
					"refresh_token": TEST_TOKEN_SECONDARY,
				}).
				Send().
				ExpectStatus(http.StatusOK).
				ExpectString("token_type", tools.TOKEN_PREFIX_BEARER).
				ExpectField("access_token").
				ExpectField("refresh_token").
				ExpectInteger("expires_in", int64(tools.LIFETIME_OAUTH2_ACCESS_TOKEN.Seconds())).
				ExpectString("scopes", TEST_OAUTH2_SCOPE_STRING)
		})

	})

	t.Run("/oauth2/token/revoke", func(t *testing.T) {

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_CONNECTION)

		t.Run("Revoke Session - Invalid Client ID", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token/revoke").
				WithBasicAuth(TEST_ID_INVALID_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"token_type_hint": "any",
					"token":           TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusUnauthorized).
				ExpectString("error", string(tools.INVALID_CLIENT)).
				ExpectString("error_description", string(tools.AUTH_FAILED))
		})

		t.Run("Revoke Session - Invalid Client Secret", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token/revoke").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_INVALID).
				WithQuery(map[string]any{
					"token_type_hint": "any",
					"token":           TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusUnauthorized).
				ExpectString("error", string(tools.INVALID_CLIENT)).
				ExpectString("error_description", string(tools.AUTH_FAILED))
		})

		t.Run("Revoke Session - Invalid Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token/revoke").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"token_type_hint": "any",
					"token":           TEST_TOKEN_INVALID,
				}).
				Send().
				ExpectStatus(http.StatusOK)
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_CONNECTION)

		t.Run("Revoke Session - Access Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token/revoke").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"token_type_hint": "any",
					"token":           TEST_TOKEN_PRIMARY,
				}).
				Send().
				ExpectStatus(http.StatusOK)
		})

		ResetDatabase(t, RESET_BASE, RESET_ACCOUNT, RESET_APPLICATION, RESET_CONNECTION)

		t.Run("Revoke Session - Refresh Token", func(t *testing.T) {
			NewTestRequest(t, "POST", "/oauth2/token/revoke").
				WithBasicAuth(TEST_ID_PRIMARY_STRING, TEST_OAUTH2_SECRET_PLAIN).
				WithQuery(map[string]any{
					"token_type_hint": "any",
					"token":           TEST_TOKEN_SECONDARY,
				}).
				Send().
				ExpectStatus(http.StatusOK)
		})

	})

}
