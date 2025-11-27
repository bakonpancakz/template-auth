package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"

	"github.com/jackc/pgx/v5"
)

func PATCH_Users_Me_Applications_ID(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}

	var Body struct {
		Name        *string   `json:"name" validate:"omitempty,displayname"`
		Description *string   `json:"description" validate:"omitempty,description"`
		Redirects   *[]string `json:"redirects" validate:"omitempty,max=100"`
	}
	if !tools.ValidateJSON(w, r, &Body) {
		return
	}
	ok, snowflake := tools.GetSnowflake(w, r)
	if !ok {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Fetch Relevant Application
	var application tools.DatabaseApplication
	err := tools.Database.QueryRow(ctx,
		`SELECT
			id, created, name, description, icon_hash, redirects
		FROM auth.applications
		WHERE id = $1 AND user_id = $2`,
		snowflake,
		session.UserID,
	).Scan(
		&application.ID,
		&application.Created,
		&application.Name,
		&application.Description,
		&application.IconHash,
		&application.AuthRedirects,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_APPLICATION)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Collect Application Edits
	edited := false
	if Body.Name != nil {
		application.Name = *Body.Name
		edited = true
	}
	if Body.Description != nil {
		if len(*Body.Description) == 0 {
			application.Description = nil
		} else {
			application.Description = Body.Description
		}
		edited = true
	}
	if Body.Redirects != nil {

		// Premature optimization rabbit hole, but this was cool :)
		// 	https://udaykishoreresu.medium.com/gos-zero-byte-secret-why-struct-outperforms-bool-for-scalable-deduplication-4de84cc8c712
		seen := make(map[string]struct{}, len(*Body.Redirects))
		redirects := make([]string, 0, len(*Body.Redirects))

		for _, str := range *Body.Redirects {

			// Canonicalize String
			canonical, err := tools.OAuth2RedirectCanonicalize(str)
			if err != nil {
				tools.SendClientError(w, r, tools.ERROR_BODY_INVALID_FIELD)
				return
			}

			// Ignore Duplicates
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			redirects = append(redirects, canonical)
		}

		application.AuthRedirects = redirects
		edited = true
	}

	if !edited {
		tools.SendClientError(w, r, tools.ERROR_BODY_EMPTY)
		return
	}

	// Apply Application Edits
	tag, err := tools.Database.Exec(ctx,
		`UPDATE auth.applications SET
			updated 	   = CURRENT_TIMESTAMP,
			name		   = $1,
			description    = $2,
			auth_redirects = $3
		WHERE id = $4 and user_id = $5`,
		application.Name,
		application.Description,
		application.AuthRedirects,
		application.ID,
		session.UserID,
	)
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	if tag.RowsAffected() == 0 {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_APPLICATION)
		return
	}

	// Organize Application
	tools.SendJSON(w, r, http.StatusOK, map[string]any{
		"id":          application.ID,
		"created":     application.Created,
		"name":        application.Name,
		"description": application.Description,
		"icon":        application.IconHash,
		"redirects":   application.AuthRedirects,
	})
}
