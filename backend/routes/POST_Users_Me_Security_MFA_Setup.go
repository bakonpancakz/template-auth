package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func POST_Users_Me_Security_MFA_Setup(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	var Body struct {
		Passcode string `json:"passcode" validate:"required,passcode"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Validate MFA Fields
	var user tools.DatabaseUser
	if err := tools.Database.QueryRow(ctx,
		"SELECT mfa_enabled, mfa_secret FROM auth.users WHERE id = $1",
		session.UserID,
	).Scan(
		&user.MFAEnabled,
		&user.MFASecret,
	); err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if user.MFAEnabled {
		tools.SendClientError(w, r, tools.ERROR_MFA_SETUP_ALREADY)
		return
	}
	if user.MFASecret == nil {
		tools.SendClientError(w, r, tools.ERROR_MFA_SETUP_NOT_INITIALIZED)
		return
	}
	if !tools.ValidateTOTPCode(Body.Passcode, *user.MFASecret) {
		tools.SendClientError(w, r, tools.ERROR_MFA_PASSCODE_INCORRECT)
		return
	}

	// Enable MFA Fields
	if _, err := tools.Database.Exec(ctx,
		"UPDATE auth.users SET mfa_enabled = TRUE WHERE id = $1",
		session.UserID,
	); err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
