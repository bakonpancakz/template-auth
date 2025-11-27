package routes

import (
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/bakonpancakz/template-auth/tools"
)

// This endpoint is unique as it doesn't return a JSON Payload
// Just saves a bit of overhead really.

func GET_Images_Category_ID_Hash_Filename(w http.ResponseWriter, r *http.Request) {

	// We perform some extensive validation here to cut down on
	// spammy or bogus S3 calls :)
	var (
		getCategory = r.PathValue("category")
		getID       = r.PathValue("id")
		getHash     = r.PathValue("hash")
		getFilename = r.PathValue("filename")
	)
	integer, err := strconv.ParseInt(getID, 10, 64)
	if err != nil || integer < 1 {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	match := tools.CompareImageHash(getHash)
	if !match {
		http.Error(w, "Invalid Hash", http.StatusBadRequest)
		return
	}
	usableName := false
	options, ok := tools.ImageOptions[getCategory]
	if !ok {
		http.Error(w, "Invalid Category", http.StatusBadRequest)
		return
	}
	for _, f := range options.Formats {
		if getFilename == f.Name {
			usableName = true
			break
		}
	}
	if !usableName {
		http.Error(w, "Invalid Filename", http.StatusBadRequest)
		return
	}

	// Download File from Bucket
	key := path.Join(options.Folder, strconv.FormatInt(integer, 10), getHash, getFilename)
	f, err := tools.Storage.Get(key)
	if err != nil {
		if errors.Is(err, tools.ErrStorageFileNotFound) {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		tools.SendServerError(w, r, err)
		return
	}

	// Stream Contents to Client
	w.Header().Set("Content-Type", tools.ImageContentType)
	io.Copy(w, f)
}
