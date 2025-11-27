package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func POST_Auth_Logout(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Revoke Current Session
	rows, err := tools.Database.Exec(ctx, `
		UPDATE auth.sessions SET
			updated = CURRENT_TIMESTAMP,
			revoked = TRUE
		WHERE id = $1 AND user_id = $2`,
		session.SessionID,
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

	// Clear Session
	http.SetCookie(w, &http.Cookie{
		Name:     tools.HTTP_COOKIE_NAME,
		Value:    "DELETED",
		Path:     "/",
		Domain:   tools.HTTP_COOKIE_DOMAIN,
		MaxAge:   -1,
		Secure:   tools.HTTP_COOKIE_SECURE,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.WriteHeader(http.StatusNoContent)
}
