package routes

import (
	"net/http"
	"strings"
	"time"

	"github.com/bakonpancakz/template-auth/tools"
)

func POST_Users_Me_Applications(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	var Body struct {
		Name string `json:"name" validate:"required,displayname"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Create New Application for Account
	var applicationID = tools.GenerateSnowflake()
	var applicationCreated = time.Now()
	var applicationSecret, _ = tools.GenerateApplicationSecret()

	_, err := tools.Database.Exec(ctx,
		`INSERT INTO auth.applications (
			id, created, updated, user_id, name, auth_secret
		) VALUES ($1, $2, $2, $3, $4, $5)`,
		applicationID,
		applicationCreated,
		session.UserID,
		strings.TrimSpace(Body.Name),
		applicationSecret,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Organize Application
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"id":          applicationID,
		"created":     applicationCreated,
		"name":        Body.Name,
		"description": nil,
		"icon":        nil,
		"redirects":   make([]string, 0),
	})
}
