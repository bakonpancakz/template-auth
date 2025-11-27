package routes

import (
	"errors"
	"io"
	"math"
	"net/http"

	"github.com/bakonpancakz/template-auth/tools"
	"github.com/jackc/pgx/v5"
)

func PUT_Users_Me_Banner(w http.ResponseWriter, r *http.Request) {

	session := tools.GetSession(r)
	if session.ApplicationID != tools.SESSION_NO_APPLICATION_ID {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_USERS_ONLY)
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
	options := tools.ImageOptionsBanners
	if ok, hash := tools.ImageHandler(w, r, options, session.UserID, uploadData); !ok {
		return
	} else {
		uploadHash = hash
	}
	defer func(id int64, hash string) {
		if !uploadOK && hash != "" {
			// Delete any possible leftover image files
			ctx, cancel := tools.NewContext()
			defer cancel()

			paths := tools.ImagePaths(options, id, hash)
			if err := tools.Storage.Delete(ctx, paths...); err != nil {
				tools.LoggerStorage.Error("Failed to delete leftover banner", map[string]any{
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
		`UPDATE auth.profiles SET
			updated 	= CURRENT_TIMESTAMP,
			banner_hash = $1
		WHERE id = $2
		RETURNING banner_hash`,
		uploadHash,
		session.UserID,
	).Scan(&previousHash)
	if errors.Is(err, pgx.ErrNoRows) {
		tools.SendClientError(w, r, tools.ERROR_UNKNOWN_USER)
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
			ctx, cancel := tools.NewContext()
			defer cancel()

			paths := tools.ImagePaths(options, session.UserID, *hash)
			if err := tools.Storage.Delete(ctx, paths...); err != nil {
				tools.LoggerStorage.Error("Failed to delete previous banner", map[string]any{
					"paths": paths,
					"error": err.Error(),
				})
			}
		}
	}(previousHash)

	w.WriteHeader(http.StatusNoContent)
}
