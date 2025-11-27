package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func DELETE_Users_Me_Security_Sessions_ID(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	if !session.Elevated {
		tools.SendClientError(w, r, tools.ERROR_MFA_ESCALATION_REQUIRED)
		return
	}
	ok, snowflake := tools.GetSnowflake(w, r)
	if !ok {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Revoke Relevant Session
	rows, err := tools.Database.Exec(ctx,
		`UPDATE auth.sessions SET
			revoked = TRUE
		WHERE id = $1
		AND user_id = $2
		AND revoked = false`,
		snowflake,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if rows.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_SESSION)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
