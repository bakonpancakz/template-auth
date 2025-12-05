package tests

import (
	"net/http"
	"testing"
	"time"

	"github.com/bakonpancakz/template-auth/tools"
)

func Test_User_Connections_Endpoints(t *testing.T) {

	t.Run("/users/@me/connections", func(t *testing.T) {

		ResetDatabase(t, RESET_BASE,
			RESET_ACCOUNT, RESET_SESSION,
			RESET_APPLICATION, RESET_APPLICATION_CUSTOMIZED,
			RESET_CONNECTION,
		)

		t.Run("GET: List Connections", func(t *testing.T) {
			var Body []struct {
				ID          int64     `json:"id" validate:"required"`
				Created     time.Time `json:"created" validate:"required"`
				Scopes      int       `json:"scopes" validate:"required"`
				Application struct {
					ID          int64     `json:"id" validate:"required"`
					Created     time.Time `json:"created" validate:"required"`
					Name        string    `json:"name" validate:"required"`
					Description string    `json:"description" validate:"required"`
					Icon        string    `json:"icon" validate:"required"`
				} `json:"application"`
			}
			NewTestRequest(t, "GET", "/users/@me/connections").
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(http.StatusOK).
				ExpectStruct(&Body)
		})

	})

	t.Run("/users/@me/connections/{id}", func(t *testing.T) {

		ResetDatabase(t,
			RESET_BASE, RESET_ACCOUNT, RESET_SESSION,
			RESET_APPLICATION, RESET_CONNECTION,
		)

		t.Run("DELETE: Revoke Connection - Not Elevated", func(t *testing.T) {
			NewTestRequest(t, "DELETE", "/users/@me/connections/%d", TEST_ID_PRIMARY).
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(tools.ERROR_MFA_ESCALATION_REQUIRED.Status).
				ExpectInteger("code", int64(tools.ERROR_MFA_ESCALATION_REQUIRED.Code)).
				ExpectString("message", tools.ERROR_MFA_ESCALATION_REQUIRED.Message)
		})

		ResetDatabase(t, RESET_SESSION_ELEVATED)

		t.Run("DELETE: Revoke Connection - Unknown ID", func(t *testing.T) {
			NewTestRequest(t, "DELETE", "/users/@me/connections/%d", TEST_ID_SECONDARY).
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(tools.ERROR_UNKNOWN_CONNECTION.Status).
				ExpectInteger("code", int64(tools.ERROR_UNKNOWN_CONNECTION.Code)).
				ExpectString("message", tools.ERROR_UNKNOWN_CONNECTION.Message)
		})

		t.Run("DELETE: Revoke Connection", func(t *testing.T) {
			NewTestRequest(t, "DELETE", "/users/@me/connections/%d", TEST_ID_PRIMARY).
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(http.StatusNoContent)

			var stateRevoked bool
			QueryDatabaseRow(t, "SELECT revoked FROM auth.connections WHERE id = $1",
				[]any{TEST_ID_PRIMARY},
				&stateRevoked,
			)
			if !stateRevoked {
				t.Fatalf("sessions was not revoked")
			}
		})

		t.Run("DELETE: Revoke Connection - Already Revoked", func(t *testing.T) {
			NewTestRequest(t, "DELETE", "/users/@me/connections/%d", TEST_ID_PRIMARY).
				WithCookie(tools.HTTP_COOKIE_NAME, TEST_TOKEN_PRIMARY).
				Send().
				ExpectStatus(tools.ERROR_UNKNOWN_CONNECTION.Status).
				ExpectInteger("code", int64(tools.ERROR_UNKNOWN_CONNECTION.Code)).
				ExpectString("message", tools.ERROR_UNKNOWN_CONNECTION.Message)
		})

	})

}
