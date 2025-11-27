package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func GET_Users_Me_Security_MFA_Codes(w http.ResponseWriter, r *http.Request) {

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

	// Fetch State for Current User
	var user tools.DatabaseUser
	err := tools.Database.QueryRow(ctx,
		`SELECT
			mfa_enabled, mfa_codes
		FROM auth.users
		WHERE id = $1`,
		session.UserID,
	).Scan(
		&user.MFAEnabled,
		&user.MFACodes,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if !user.MFAEnabled {
		tools.SendClientError(w, r, tools.ERROR_MFA_DISABLED)
		return
	}

	// Organize Account
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"recovery_codes": user.MFACodes,
	})
}
