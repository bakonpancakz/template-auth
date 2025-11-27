package routes

import (
	"errors"
	"io"
	"math"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
	"github.com/jackc/pgx/v5"
)

/*
 * Technically we should check to see if the user actually owns the application
 * before committing to all this effort, but the chances of this happening are low
 * and the ratelimit is so aggressive that I feel it's worth skipping a preemptive
 * database query :P
 */

func PUT_Users_Me_Applications_ID_Icon(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
		return
	}
	ok, snowflake := tools.GetSnowflake(w, r)
	if !ok {
		return
	}
	if err := r.ParseMultipartForm(math.MaxInt64); err != nil {
		tools.SendClientError(w, r, tools.ERROR_BODY_INVALID_TYPE)
		return
	}

	// Copy incoming image to memory
	var uploadData []byte
	var uploadHash string
	var uploadOK bool
	if file, _, err := r.FormFile("image"); err != nil {
		tools.SendClientError(w, r, tools.ERROR_BODY_INVALID_FIELD)
		return
	} else if data, err := io.ReadAll(file); err != nil {
		tools.SendClientError(w, r, tools.ERROR_BODY_INVALID_DATA)
		return
	} else {
		file.Close()
		uploadData = data
	}

	// Resize and store incoming image
	options := tools.ImageOptionsIcons
	if ok, hash := tools.ImageHandler(w, r, options, session.UserID, uploadData); !ok {
		return
	} else {
		uploadHash = hash
	}
	defer func(id int64, hash string) {
		if !uploadOK && hash != "" {
			// Delete any possible leftover image files
			paths := tools.ImagePaths(options, id, hash)
			if err := tools.Storage.Delete(paths...); err != nil {
				tools.LoggerStorage.Error("Failed to delete leftover icon", map[string]any{
					"paths": paths,
					"error": err.Error(),
				})
			}
		}
	}(session.UserID, uploadHash)

	// Store updated image hash
	ctx, cancel := tools.NewContext()
	defer cancel()

	var previousHash *string
	err := tools.Database.QueryRow(ctx,
		`UPDATE auth.applications SET
			updated   = CURRENT_TIMESTAMP,
			icon_hash = $1
		WHERE id = $2 AND user_id = $3
		RETURNING icon_hash`,
		uploadHash,
		snowflake,
		session.UserID,
	).Scan(&previousHash)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_APPLICATION)
		return
	}
	if err != nil {
		tools.SendServerError(w, r, err)
		return
	}
	uploadOK = true

	// Delete previous images (if any)
	go func(hash *string) {
		if hash != nil {
			paths := tools.ImagePaths(options, session.UserID, *hash)
			if err := tools.Storage.Delete(paths...); err != nil {
				tools.LoggerStorage.Error("Failed to delete previous icon", map[string]any{
					"paths": paths,
					"error": err.Error(),
				})
			}
		}
	}(previousHash)

	w.WriteHeader(http.StatusNoContent)
}
