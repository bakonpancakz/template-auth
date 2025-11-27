package routes

import (
	"fmt"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func GET_Users_Me_Security_MFA_Setup(w http.ResponseWriter, r *http.Request) {

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
	var profile tools.DatabaseProfile
	err := tools.Database.QueryRow(ctx,
		`SELECT
			u.email_address, u.mfa_enabled, p.username
		FROM auth.users u
		JOIN auth.profiles p ON u.id = p.id
		WHERE u.id = $1`,
		session.UserID,
	).Scan(
		&user.EmailAddress,
		&user.MFAEnabled,
		&profile.Username,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if user.MFAEnabled {
		tools.SendClientError(w, r, tools.ERROR_MFA_SETUP_ALREADY)
		return
	}

	// Generate MFA State
	setupCodes := tools.GenerateRecoveryCodes()
	setupSecret := tools.GenerateTOTPSecret()
	setupURI := tools.GenerateTOTPURI(
		"Auth", fmt.Sprintf("%s (%s)", profile.Username, user.EmailAddress),
		setupSecret,
	)

	// Update State for Current User
	if _, err = tools.Database.Exec(ctx,
		`UPDATE auth.users SET
			updated 		= CURRENT_TIMESTAMP,
			mfa_enabled 	= false,
			mfa_secret 		= $2,
			mfa_codes 		= $3,
			mfa_codes_used 	= 0
		WHERE id = $1`,
		session.UserID,
		setupSecret,
		setupCodes,
	); err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Organize Setup
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"recovery_codes": setupCodes,
		"secret":         setupSecret,
		"uri":            setupURI,
	})
}
