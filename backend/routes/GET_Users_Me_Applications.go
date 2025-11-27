package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func GET_Users_Me_Applications(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Applications for Account
	rows, err := tools.Database.Query(ctx,
		`SELECT
			id, created, name, description, icon_hash, redirects
		FROM auth.applications
		WHERE user_id = $1`,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	defer rows.Close()

	// Organize Applications
	var results = make([]map[string]any, 0, 1)
	var app tools.DatabaseApplication
	for rows.Next() {
		err := rows.Scan(
			&app.ID,
			&app.Created,
			&app.Name,
			&app.Description,
			&app.IconHash,
			&app.AuthRedirects,
		)
		if err != nil {
			tools.SendServerError(w, r, err)
			return
		}
		results = append(results, map[string]any{
			"id":          app.ID,
			"created":     app.Created,
			"name":        app.Name,
			"description": app.Description,
			"icon":        app.IconHash,
			"redirects":   app.AuthRedirects,
		})
	}

	tools.SendJSON(w, r, http.StatusOK, results)
}
