package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func GET_OAuth2_Authorize(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	var Body struct {
		State        *string `query:"state"`
		ClientID     int64   `query:"client_id"`
		ResponseType string  `query:"response_type"`
		RedirectURI  string  `query:"redirect_uri"`
		ScopesString string  `query:"scope"`
	}
	if !tools.BindQuery(w, r, &Body) {
		return
	}

	// Additional Validation
	if Body.ClientID < 1 {
		tools.SendOAuth2Error(w, r, tools.INVALID_REQUEST, tools.CLIENT_ID_INVALID)
		return
	}
	if Body.ResponseType != "code" {
		tools.SendOAuth2Error(w, r, tools.UNSUPPORTED_RESPONSE_TYPE, tools.RESPONSE_TYPE_EXPECT_CODE)
		return
	}
	ok, requestedScopes := tools.OAuth2ValidateRequestScopes(w, r, Body.ScopesString)
	if !ok {
		return
	}
	ok, Body.RedirectURI = tools.OAuth2ValidateRedirectURI(w, r, Body.RedirectURI)
	if !ok {
		return
	}

	// Fetch Relevant Application
	ctx, cancel := tools.NewContext()
	defer cancel()

	var application tools.DatabaseApplication
	err := tools.Database.QueryRow(ctx,
		`SELECT
			id, created, name, icon_hash, auth_redirects
		FROM auth.applications
		WHERE id = $1`,
		Body.ClientID,
	).Scan(
		&application.ID,
		&application.Created,
		&application.Name,
		&application.IconHash,
		&application.AuthRedirects,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendOAuth2Error(w, r, tools.INVALID_REQUEST, tools.UNKNOWN_APPLICATION)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Validate Requested URI
	requestedRedirect, err := tools.OAuth2RedirectCompare(Body.RedirectURI, application.AuthRedirects)
	if err != nil {
		tools.SendOAuth2Error(w, r, tools.INVALID_REQUEST, tools.REDIRECT_DISALLOWED)
		return
	}

	// Fetch Relevant Profile
	var profile tools.DatabaseProfile
	err = tools.Database.QueryRow(ctx,
		`SELECT
			id, displayname, avatar_hash
		FROM auth.profiles
		WHERE id = $1`,
		session.UserID,
	).Scan(
		&profile.ID,
		&profile.Displayname,
		&profile.AvatarHash,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendOAuth2Error(w, r, tools.INVALID_REQUEST, tools.UNKNOWN_APPLICATION)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Organize Application and Profile
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"redirect": requestedRedirect,
		"scopes":   requestedScopes,
		"state":    Body.State,
		"application": map[string]any{
			"id":      application.ID,
			"created": application.Created,
			"name":    application.Name,
			"icon":    application.IconHash,
		},
		"user": map[string]any{
			"id":          profile.ID,
			"displayname": profile.Displayname,
			"avatar":      profile.AvatarHash,
		},
	})
}
