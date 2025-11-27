package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func GET_Users_Me_Connections(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Account Connections
	rows, err := tools.Database.Query(ctx,
		`SELECT
			c.id, c.created, c.scopes,
			a.id, a.created, a.name, a.description, a.icon_hash
		FROM auth.connections c
		INNER JOIN auth.applications a ON c.application_id = a.id
		WHERE c.user_id = $1 AND c.revoked = FALSE`,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	defer rows.Close()

	// Organize Connections
	var connection tools.DatabaseConnection
	var application tools.DatabaseApplication
	results := make([]map[string]any, 0, 1)
	for rows.Next() {
		if err := rows.Scan(
			&connection.ID,
			&connection.Created,
			&connection.Scopes,
			&application.ID,
			&application.Created,
			&application.Name,
			&application.Description,
			&application.IconHash,
		); err != nil {
			tools.SendServerError(w, r, err)
			return
		}
		results = append(results, map[string]any{
			"id":      connection.ID,
			"created": connection.Created,
			"scopes":  connection.Scopes,
			"application": map[string]any{
				"id":          application.ID,
				"created":     application.Created,
				"name":        application.Name,
				"description": application.Description,
				"icon":        application.IconHash,
			},
		})
	}
	tools.SendJSON(w, r, http.StatusOK, results)
}
