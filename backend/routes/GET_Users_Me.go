package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func GET_Users_Me(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if !tools.OAuth2ScopesContains(session, tools.SCOPE_READ_IDENTIFY) {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_SCOPE_REQUIRED)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Relevant Account and Profile
	var user tools.DatabaseUser
	var profile tools.DatabaseProfile
	err := tools.Database.QueryRow(ctx,
		`SELECT
			u.id, u.created, u.email_address, u.email_verified, u.mfa_enabled,
			p.username, p.displayname, p.biography, p.subtitle, p.avatar_hash,
			p.banner_hash, p.accent_banner, p.accent_border, p.accent_background
		FROM auth.users u
		JOIN auth.profiles p ON u.id = p.id
		WHERE u.id = $1`,
		session.UserID,
	).Scan(
		&user.ID, &user.Created, &user.EmailAddress, &user.EmailVerified, &user.MFAEnabled,
		&profile.Username, &profile.Displayname, &profile.Biography, &profile.Subtitle, &profile.AvatarHash,
		&profile.BannerHash, &profile.AccentBanner, &profile.AccentBorder, &profile.AccentBackground,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Hide email if connection is missing optional scopes
	var emailAddress *string = &user.EmailAddress
	if !tools.OAuth2ScopesContains(session, tools.SCOPE_READ_EMAIL) {
		emailAddress = nil
	}

	// Organize Account & Profile
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"id":                user.ID,
		"created":           user.Created,
		"username":          profile.Username,
		"displayname":       profile.Displayname,
		"biography":         profile.Biography,
		"subtitle":          profile.Subtitle,
		"avatar":            profile.AvatarHash,
		"banner":            profile.BannerHash,
		"accent_banner":     profile.AccentBanner,
		"accent_border":     profile.AccentBorder,
		"accent_background": profile.AccentBackground,
		"email":             emailAddress,
		"verified":          user.EmailVerified,
		"mfa_enabled":       user.MFAEnabled,
	})
}
