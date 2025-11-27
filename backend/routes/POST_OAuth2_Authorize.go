package routes

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func POST_OAuth2_Authorize(w http.ResponseWriter, r *http.Request) {

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

	// Fetch State for Requested Application
	ctx, cancel := tools.NewContext()
	defer cancel()

	var application tools.DatabaseApplication
	err := tools.Database.QueryRow(ctx,
		"SELECT id, auth_redirects FROM auth.applications WHERE id = $1",
		Body.ClientID,
	).Scan(
		&application.ID,
		&application.AuthRedirects,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendOAuth2Error(w, r, tools.INVALID_CLIENT, tools.UNKNOWN_APPLICATION)
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

	// Generate Temporary Grant Session
	grantCode := tools.GenerateSignedString()
	if _, err := tools.Database.Exec(ctx,
		`INSERT INTO auth.grants (
			id, expires, user_id, application_id, redirect_uri, scopes, code
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		tools.GenerateSnowflake(),
		time.Now().Add(tools.LIFETIME_OAUTH2_GRANT_TOKEN),
		session.UserID,
		application.ID,
		requestedRedirect,
		requestedScopes,
		grantCode,
	); err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Redirect User to Requested URI with Grant
	q := url.Values{}
	q.Add("code", grantCode)
	if Body.State != nil {
		q.Add("state", *Body.State)
	}
	http.Redirect(w, r, fmt.Sprint(requestedRedirect, "?", q.Encode()), http.StatusFound)
}
