package routes

import (
	"errors"
	"net/http"
	"time"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func POST_OAuth2_Token(w http.ResponseWriter, r *http.Request) {

	var Body struct {
		GrantType    string `query:"grant_type"`    // Required
		RedirectURI  string `query:"redirect_uri"`  // Used in Grant Code
		Code         string `query:"code"`          // Used in Grant Code
		RefreshToken string `query:"refresh_token"` // Used in Grant Refresh
	}
	if !tools.BindQuery(w, r, &Body) {
		return
	}

	// Validate Parameters
	switch Body.GrantType {
	case tools.GRANT_CODE:
		if !tools.CompareSignedString(Body.Code) {
			tools.SendOAuth2Error(w, r, tools.INVALID_REQUEST, tools.CODE_INVALID)
			return
		}
		ok, standard := tools.OAuth2ValidateRedirectURI(w, r, Body.RedirectURI)
		if !ok {
			return
		}
		Body.RedirectURI = standard
	case tools.GRANT_REFRESH:
		if !tools.CompareSignedString(Body.RefreshToken) {
			tools.SendOAuth2Error(w, r, tools.INVALID_GRANT, tools.REFRESH_TOKEN_UNKNOWN)
			return
		}
	default:
		tools.SendOAuth2Error(w, r, tools.UNSUPPORTED_GRANT_TYPE, tools.GRANT_TYPE_UNSUPPORTED)
		return
	}

	// Validate Application Secret
	ctx, cancel := tools.NewContext()
	defer cancel()
	ok, applicationID := tools.OAuth2ValidateRequestAuth(ctx, w, r)
	if !ok {
		return
	}

	// Complete Grant Request
	switch Body.GrantType {

	// Consume Auth Grant
	case tools.GRANT_CODE:
		var grant tools.DatabaseGrant
		err := tools.Database.QueryRow(ctx,
			`DELETE FROM auth.grants
			WHERE code = $1
			AND application_id = $2
			AND redirect_uri = $3
			AND expires > NOW()
			RETURNING user_id, application_id, scopes`,
			Body.Code,
			applicationID,
			Body.RedirectURI,
		).Scan(
			&grant.UserID,
			&grant.ApplicationID,
			&grant.Scopes,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			tools.SendOAuth2Error(w, r, tools.INVALID_GRANT, tools.GRANT_UNKNOWN)
			return
		}
		if err != nil {
			tools.SendServerError(w, r, err)
			return
		}

		// Update or Create New Connection
		var tokenAccess = tools.GenerateSignedString()
		var tokenRefresh = tools.GenerateSignedString()
		var tokenExpires = time.Now().Add(tools.LIFETIME_OAUTH2_ACCESS_TOKEN)
		_, err = tools.Database.Exec(ctx, `
			INSERT INTO auth.connections (
				id, user_id, application_id, scopes, token_access,
				token_expires, token_refresh
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (user_id, application_id)
			DO UPDATE SET
				updated       = CURRENT_TIMESTAMP,
				revoked       = FALSE,
				scopes        = $4,
				token_access  = $5,
				token_refresh = $7,
				token_expires = $6;
			`,
			tools.GenerateSnowflake(),
			grant.UserID,
			grant.ApplicationID,
			grant.Scopes,
			tokenAccess,
			tokenExpires,
			tokenRefresh,
		)
		if err != nil {
			tools.SendServerError(w, r, err)
			return
		}

		// Organize Grant
		tools.SendJSON(w, r, http.StatusOK, map[string]any{
			"token_type":    tools.TOKEN_PREFIX_BEARER,
			"access_token":  tokenAccess,
			"refresh_token": tokenRefresh,
			"expires_in":    int(tools.LIFETIME_OAUTH2_ACCESS_TOKEN.Seconds()),
			"scopes":        tools.OAuth2ScopesToString(grant.Scopes),
		})
		return

	// Search for Relevant Connection
	case tools.GRANT_REFRESH:
		var connection tools.DatabaseConnection
		err := tools.Database.QueryRow(ctx,
			`SELECT
				id, scopes
			FROM auth.connections
			WHERE token_refresh = $1
			AND application_id 	= $2
			AND revoked = FALSE`,
			Body.RefreshToken,
			applicationID,
		).Scan(
			&connection.ID,
			&connection.Scopes,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			tools.SendOAuth2Error(w, r, tools.INVALID_GRANT, tools.REFRESH_TOKEN_UNKNOWN)
			return
		}
		if err != nil {
			tools.SendServerError(w, r, err)
			return
		}

		// Update Connection Tokens
		var tokenAccess = tools.GenerateSignedString()
		var tokenRefresh = tools.GenerateSignedString()
		_, err = tools.Database.Exec(ctx,
			`UPDATE auth.connections SET
				updated 	  = CURRENT_TIMESTAMP,
				token_access  = $1,
				token_refresh = $2,
				token_expires = $3
			WHERE id = $4`,
			tokenAccess,
			tokenRefresh,
			time.Now().Add(tools.LIFETIME_OAUTH2_ACCESS_TOKEN),
			connection.ID,
		)
		if err != nil {
			tools.SendServerError(w, r, err)
			return
		}

		// Organize Connection
		tools.SendJSON(w, r, http.StatusOK, map[string]any{
			"token_type":    tools.TOKEN_PREFIX_BEARER,
			"access_token":  tokenAccess,
			"refresh_token": tokenRefresh,
			"expires_in":    int(tools.LIFETIME_OAUTH2_ACCESS_TOKEN.Seconds()),
			"scopes":        tools.OAuth2ScopesToString(connection.Scopes),
		})
		return
	}
}
