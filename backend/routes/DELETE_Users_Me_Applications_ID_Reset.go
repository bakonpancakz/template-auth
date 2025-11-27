package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func DELETE_Users_Me_Applications_ID_Reset(w http.ResponseWriter, r *http.Request) {

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

	// Generate New Secret Key for Application
	secretPlain, secretHashed := tools.GenerateApplicationSecret()
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.applications SET
			updated = CURRENT_TIMESTAMP,
			auth_secret = $1
		WHERE id = $2 AND user_id = $3`,
		secretHashed,
		snowflake,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_APPLICATION)
		return
	}

	// Organize Application
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"secret": secretPlain,
	})
}
