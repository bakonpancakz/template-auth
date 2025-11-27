package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
	"github.com/jackc/pgx/v5"
)

func DELETE_Users_Me_Applications_ID_Icon(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ok, snowflake := tools.GetSnowflake(w, r)
	if !ok {
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Remove Image from Application
	var hash *string
	err := tools.Database.QueryRow(ctx,
		`UPDATE auth.applications SET
			icon_hash = NULL
		WHERE id = $1 AND user_id = $2
		RETURNING icon_hash`,
		snowflake, session.UserID,
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_APPLICATION)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Delete Icon from Storage
	if hash == nil {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_IMAGE)
		return
	}
	go func(h string) {
		paths := tools.ImagePaths(tools.ImageOptionsIcons, snowflake, h)
		if err := tools.Storage.Delete(paths...); err != nil {
			tools.LoggerStorage.Error("Failed to Delete Application Icon", map[string]any{
				"paths": paths,
				"error": err.Error(),
			})
		}
	}(*hash)

	w.WriteHeader(http.StatusNoContent)
}
