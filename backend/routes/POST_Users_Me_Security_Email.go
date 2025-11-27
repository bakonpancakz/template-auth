package routes

import (
	"errors"
	"net/http"
	"time"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func POST_Users_Me_Security_Email(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Update Email Verification Fields for Account
	var (
		user               tools.DatabaseUser
		verifyToken        = tools.GenerateSignedString()
		verifyTokenExpires = time.Now().Add(tools.LIFETIME_TOKEN_EMAIL_VERIFY)
	)
	err := tools.Database.QueryRow(ctx,
		`UPDATE auth.users SET
			updated 		 = CURRENT_TIMESTAMP,
			token_verify 	 = $1,
			token_verify_eat = $2
		WHERE id = $3 AND email_verified = FALSE
		RETURNING email_address`,
		verifyToken,
		verifyTokenExpires,
		session.UserID,
	).Scan(&user)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_MFA_EMAIL_ALREADY_VERIFIED)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Send Email to Account Owner
	go func() {
		subCtx, subCancel := tools.NewContext()
		defer subCancel()

		// Fetch Displayname
		displayname := tools.EMAIL_DEFAULT_DISPLAYNAME
		tools.Database.
			QueryRow(subCtx, "SELECT displayname FROM auth.profiles WHERE user_id = $1", user.ID).
			Scan(&displayname)

		// Send Email
		tools.TemplateEmailVerify(
			user.EmailAddress,
			tools.LocalsEmailVerify{
				Displayname: displayname,
				Token:       verifyToken,
			},
		)
	}()

	w.WriteHeader(http.StatusNoContent)
}
