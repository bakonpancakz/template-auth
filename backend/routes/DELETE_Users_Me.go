package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func DELETE_Users_Me(w http.ResponseWriter, r *http.Request) {

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

	// Fetch User Account and Profile
	var imagePaths = make([]string, 0, 3)
	var profile tools.DatabaseProfile
	var user tools.DatabaseUser
	err := tools.Database.QueryRow(ctx,
		`SELECT
			u.id, u.email_address, u.email_verified, p.displayname,
			p.avatar_hash, p.banner_hash
		FROM auth.users u
		JOIN auth.profiles p ON u.id = p.id
		WHERE u.id = $1`,
		session.UserID,
	).Scan(
		&user.ID,
		&user.EmailAddress,
		&user.EmailVerified,
		&profile.Displayname,
		&profile.AvatarHash,
		&profile.BannerHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Fetch User Applications
	rows, err := tools.Database.Query(ctx,
		"SELECT id, icon_hash FROM auth.applications WHERE user_id = $1",
		user.ID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	defer rows.Close()

	// Generate Image Paths
	for rows.Next() {
		var applicationID int64
		var applicationIcon *string
		if err := rows.Scan(&applicationID, &applicationIcon); err != nil {
			tools.SendServerError(w, r, err)
			return
		}
		if applicationIcon != nil {
			imagePaths = append(imagePaths,
				tools.ImagePaths(tools.ImageOptionsIcons, applicationID, *applicationIcon)...,
			)
		}
	}
	if profile.AvatarHash != nil {
		imagePaths = append(imagePaths,
			tools.ImagePaths(tools.ImageOptionsAvatars, user.ID, *profile.AvatarHash)...,
		)
	}
	if profile.BannerHash != nil {
		imagePaths = append(imagePaths,
			tools.ImagePaths(tools.ImageOptionsBanners, user.ID, *profile.BannerHash)...,
		)
	}

	// Delete Account (Assuming this cascades properly)
	tag, err := tools.Database.Exec(ctx, "DELETE FROM auth.users WHERE id = $1", user.ID)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}

	// Background Tasks
	// 	Delete Account Images
	//	Notify Account Owner of Deletion
	go tools.Storage.Delete(imagePaths...)
	go tools.TemplateNotifyUserDeleted(
		user.EmailAddress,
		tools.LocalsNotifyUserDeleted{
			Displayname: profile.Displayname,
			Reason:      "User Request",
		},
	)

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
