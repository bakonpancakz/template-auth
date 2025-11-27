package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

// Respond with '200 OK' status code even if invalid per standard
// https://datatracker.ietf.org/doc/html/rfc7009#section-2.2

func POST_OAuth2_Token_Revoke(w http.ResponseWriter, r *http.Request) {

	var Body struct {
		// Not used, but this field is parsed anyways to prevent a possible
		// 'disallowed field' validation error from happening in the future
		// as some OAuth2 Libraries may include it.
		TokenTypeHint string `query:"token_type_hint"`
		Token         string `query:"token"`
	}
	if !tools.BindQuery(w, r, &Body) {
		return
	}
	if !tools.CompareSignedString(Body.Token) {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate Application Secret
	ctx, cancel := tools.NewContext()
	defer cancel()
	ok, applicationID := tools.OAuth2ValidateRequestAuth(ctx, w, r)
	if !ok {
		return
	}

	// Mark Relevant Connection as Revoked
	_, err := tools.Database.Exec(ctx,
		`UPDATE auth.connections SET
			updated = CURRENT_TIMESTAMP,
			revoked = TRUE,
			scopes	= 0
		WHERE (token_access = $1 OR token_refresh = $1)
		AND application_id = $2
		AND revoked = false`,
		Body.Token,
		applicationID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusOK)
}
