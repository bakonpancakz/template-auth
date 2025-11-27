package routes

import (
	"errors"
	"net/http"
	"time"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func PATCH_Users_Me_Security_Email(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	if !session.Elevated {
		tools.SendClientError(w, r, tools.ERROR_MFA_ESCALATION_REQUIRED)
		return
	}

	var Body struct {
		Email string `json:"email" validate:"required,email"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Check for Duplicate Email
	var usageEmail int
	err := tools.Database.
		QueryRow(ctx, "SELECT COUNT(*) FROM auth.users WHERE email_address = LOWER($1)", Body.Email).
		Scan(&usageEmail)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if usageEmail > 0 {
		tools.SendClientError(w, r, tools.ERROR_SIGNUP_DUPLICATE_EMAIL)
		return
	}

	// Update Account Email Fields
	var userEmailPrevious string
	var userVerifyToken = tools.GenerateSignedString()
	err = tools.Database.QueryRow(ctx,
		`UPDATE auth.users SET
			updated			 	= CURRENT_TIMESTAMP,
			email_verified 		= FALSE,
			email_address 	 	= LOWER($1),
			token_verify 	 	= $2,
			token_verify_eat 	= $3
		WHERE id = $4
		RETURNING (SELECT email_address FROM auth.users WHERE id = $4)`,
		Body.Email,
		userVerifyToken,
		time.Now().Add(tools.LIFETIME_TOKEN_EMAIL_VERIFY),
		session.UserID,
	).Scan(&userEmailPrevious)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Send Emails
	go func() {
		subCtx, subCancel := tools.NewContext()
		defer subCancel()

		// Fetch Displayname
		displayname := tools.EMAIL_DEFAULT_DISPLAYNAME
		tools.Database.
			QueryRow(subCtx, "SELECT displayname FROM auth.profiles WHERE user_id = $1", session.UserID).
			Scan(&displayname)

		// Send Verification Email
		tools.TemplateEmailVerify(
			Body.Email,
			tools.LocalsEmailVerify{
				Displayname: displayname,
				Token:       userVerifyToken,
			},
		)
		// Notify Account Owner
		tools.TemplateNotifyUserEmailModified(
			userEmailPrevious,
			tools.LocalsNotifyUserEmailModified{
				Displayname: displayname,
			},
		)
	}()

	w.WriteHeader(http.StatusNoContent)
}
