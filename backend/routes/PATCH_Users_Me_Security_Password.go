package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func PATCH_Users_Me_Security_Password(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}

	var Body struct {
		OldPassword string `json:"old_password" validate:"required,password"`
		NewPassword string `json:"new_password" validate:"required,password"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Account Password Fields
	var user tools.DatabaseUser
	err := tools.Database.QueryRow(ctx,
		`SELECT
			email_address, password_hash, password_history
		FROM auth.users
		WHERE id = $1`,
		session.UserID,
	).Scan(
		&user.EmailAddress,
		&user.PasswordHash,
		&user.PasswordHistory,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Validate Old Password
	if user.PasswordHash == nil {
		tools.SendClientError(w, r, tools.ERROR_LOGIN_PASSWORD_RESET)
		return
	}
	if ok, err := tools.ComparePasswordHash(*user.PasswordHash, Body.OldPassword); err != nil {
		tools.SendServerError(w, r, err)
		return
	} else if !ok {
		tools.SendClientError(w, r, tools.ERROR_MFA_PASSWORD_INCORRECT)
		return
	}

	// Append Unique Password to History
	for _, oldPassword := range user.PasswordHistory {
		if ok, err := tools.ComparePasswordHash(oldPassword, Body.NewPassword); err != nil {
			tools.SendServerError(w, r, err)
			return
		} else if !ok {
			tools.SendClientError(w, r, tools.ERROR_LOGIN_PASSWORD_ALREADY_USED)
			return
		}
	}
	latestPasswordHash, err := tools.GeneratePasswordHash(Body.NewPassword)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	user.PasswordHistory = append(user.PasswordHistory, latestPasswordHash)
	if len(user.PasswordHistory) > tools.PASSWORD_HISTORY_LIMIT {
		user.PasswordHistory = user.PasswordHistory[1:]
	}

	// Update Account Password Fields
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.users SET
			updated			 = CURRENT_TIMESTAMP,
			password_hash	 = $1,
			password_history = $2
		WHERE id = $3`,
		latestPasswordHash,
		user.PasswordHistory,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}

	// Notify Account Owner
	go func() {
		subCtx, subCancel := tools.NewContext()
		defer subCancel()

		// Fetch Displayname
		displayname := tools.EMAIL_DEFAULT_DISPLAYNAME
		tools.Database.
			QueryRow(subCtx, "SELECT displayname FROM auth.profiles WHERE user_id = $1", user.ID).
			Scan(&displayname)

			// Send Email
		tools.TemplateNotifyUserPasswordModified(
			user.EmailAddress,
			tools.LocalsNotifyUserPasswordModified{
				Displayname: displayname,
			},
		)
	}()

	// Revoke All Account Sessions
	if _, err := tools.Database.Exec(ctx,
		"DELETE FROM auth.sessions WHERE user_id = $1 AND id != $2",
		session.UserID,
		session.SessionID,
	); err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
