package routes

import (
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
)

func GET_Users_Me_Security_Sessions(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Sessions for Account
	rows, err := tools.Database.Query(ctx,
		`SELECT
			id, device_ip_address, device_user_agent
		FROM auth.sessions
		WHERE user_id = $1`,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	defer rows.Close()

	// Organize Sessions
	var results = make([]map[string]any, 0, 1)
	var login tools.DatabaseSession
	for rows.Next() {
		if err := rows.Scan(
			&login.ID,
			&login.DeviceIPAddress,
			&login.DeviceUserAgent,
		); err != nil {
			tools.SendServerError(w, r, err)
			return
		}
		results = append(results, map[string]any{
			"id":       login.ID,
			"location": tools.LookupLocation(login.DeviceIPAddress),
			"browser":  tools.LookupBrowser(login.DeviceUserAgent),
		})
	}

	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"current":  session.SessionID,
		"sessions": results,
	})
}
