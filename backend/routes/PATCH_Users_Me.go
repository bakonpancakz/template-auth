package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func PATCH_Users_Me(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}

	var Body struct {
		Displayname      *string `json:"displayname" validate:"omitempty,displayname"`
		Subtitle         *string `json:"subtitle" validate:"omitempty,displayname"`
		Biography        *string `json:"biography" validate:"omitempty,description"`
		AccentBanner     *int    `json:"accent_banner" validate:"omitempty,color"`
		AccentBorder     *int    `json:"accent_border" validate:"omitempty,color"`
		AccentBackground *int    `json:"accent_background" validate:"omitempty,color"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Relevant Profile
	var profile tools.DatabaseProfile
	err := tools.Database.QueryRow(ctx,
		`SELECT
			username, displayname, biography, subtitle, avatar_hash,
			banner_hash, accent_banner, accent_border, accent_background
		FROM auth.profiles
		WHERE id = $1`,
		session.UserID,
	).Scan(
		&profile.Username,
		&profile.Displayname,
		&profile.Biography,
		&profile.Subtitle,
		&profile.AvatarHash,
		&profile.BannerHash,
		&profile.AccentBanner,
		&profile.AccentBorder,
		&profile.AccentBackground,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	} else if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Collect Profile Edits
	edited := false
	if Body.Displayname != nil {
		if len(*Body.Displayname) == 0 {
			profile.Displayname = profile.Username
		} else {
			profile.Displayname = *Body.Displayname
		}
		edited = true
	}
	if Body.Subtitle != nil {
		if len(*Body.Subtitle) == 0 {
			profile.Subtitle = nil
		} else {
			profile.Subtitle = Body.Subtitle
		}
		edited = true
	}
	if Body.Biography != nil {
		if len(*Body.Biography) == 0 {
			profile.Biography = nil
		} else {
			profile.Biography = Body.Biography
		}
		edited = true
	}
	if Body.AccentBanner != nil {
		if *Body.AccentBanner == 0 {
			profile.AccentBanner = nil
		} else {
			profile.AccentBanner = Body.AccentBanner
		}
		edited = true
	}
	if Body.AccentBorder != nil {
		if *Body.AccentBorder == 0 {
			profile.AccentBorder = nil
		} else {
			profile.AccentBorder = Body.AccentBorder
		}
		edited = true
	}
	if Body.AccentBackground != nil {
		if *Body.AccentBackground == 0 {
			profile.AccentBackground = nil
		} else {
			profile.AccentBackground = Body.AccentBackground
		}
		edited = true
	}

	if !edited {
		tools.SendClientError(w, r, tools.ERROR_BODY_EMPTY)
		return
	}

	// Apply Profile Edits
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.profiles SET
			updated 		  = CURRENT_TIMESTAMP,
			displayname 	  = $1,
			subtitle 		  = $2,
			biography		  = $3,
			accent_banner 	  = $4,
			accent_border	  = $5,
			accent_background = $6
		WHERE id = $7`,
		profile.Displayname,
		profile.Subtitle,
		profile.Biography,
		profile.AccentBanner,
		profile.AccentBorder,
		profile.AccentBackground,
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

	// Organize Profile
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"username":          profile.Username,
		"displayname":       profile.Displayname,
		"biography":         profile.Biography,
		"subtitle":          profile.Subtitle,
		"avatar":            profile.AvatarHash,
		"banner":            profile.BannerHash,
		"accent_banner":     profile.AccentBanner,
		"accent_border":     profile.AccentBorder,
		"accent_background": profile.AccentBackground,
	})
}
