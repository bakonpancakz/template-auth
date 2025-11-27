package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func DELETE_Users_Me_Security_MFA_Setup(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	if !session.Elevated {
		tools.SendClientError(w, r, tools.ERROR_MFA_ESCALATION_REQUIRED)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Clear Fields for Current User
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.users SET
			updated 		= CURRENT_TIMESTAMP,
			mfa_enabled 	= false,
			mfa_secret	 	= NULL,
			mfa_codes 		= '{}',
			mfa_codes_used 	= 0
		WHERE id = $1 AND mfa_enabled = TRUE`,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_MFA_DISABLED)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
