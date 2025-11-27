package routes

import (
	"errors"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
	"github.com/jackc/pgx/v5"
)

func DELETE_Users_Me_Banner(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ctx, cancel := tools.NewContext()
	defer cancel()

	// Remove Banner from Profile
	var hash *string
	err := tools.Database.QueryRow(ctx,
		`UPDATE auth.profiles SET
			banner_hash = NULL
		WHERE id = $1
		RETURNING banner_hash`,
		session.UserID,
	).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}

	// Delete Banner from Storage
	if hash == nil {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_IMAGE)
		return
	}
	go func(h string) {
		paths := tools.ImagePaths(tools.ImageOptionsBanners, session.UserID, h)
		if err := tools.Storage.Delete(paths...); err != nil {
			tools.LoggerStorage.Error("Failed to Delete Profile Banner", map[string]any{
				"paths": paths,
				"error": err.Error(),
			})
		}
	}(*hash)

	w.WriteHeader(http.StatusNoContent)
}
