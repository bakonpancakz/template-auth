package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func DELETE_Users_Me_Security_MFA_Codes(w http.ResponseWriter, r *http.Request) {

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

	// Generate New Recovery Codes for Current User
	recoveryCodes := tools.GenerateRecoveryCodes()
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.users SET
			updated 		= CURRENT_TIMESTAMP,
			mfa_codes 		= $1,
			mfa_codes_used 	= 0
		WHERE id = $2 AND mfa_enabled = TRUE`,
		recoveryCodes,
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

	// Organize Account
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"recovery_codes": recoveryCodes,
	})
}
