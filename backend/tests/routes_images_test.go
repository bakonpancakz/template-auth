package tests

import (
	"net/http"
	"testing"
)

func Test_Image_Endpoints(t *testing.T) {

	t.Run("Get Image - Invalid Category", func(t *testing.T) {
		NewTestRequest(t, "GET", "/images/INVALID/1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/md.jpeg").
			Send().
			ExpectStatus(http.StatusBadRequest)
	})

	t.Run("Get Image - Invalid ID", func(t *testing.T) {
		NewTestRequest(t, "GET", "/images/avatars/INVALID/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/md.jpeg").
			Send().
			ExpectStatus(http.StatusBadRequest)
	})

	t.Run("Get Image - Invalid Hash", func(t *testing.T) {
		NewTestRequest(t, "GET", "/images/avatars/1/INVALIDINVALIDINVALIDINVALIDINVA/md.jpeg").
			Send().
			ExpectStatus(http.StatusBadRequest)
	})

	t.Run("Get Image - Invalid Filename", func(t *testing.T) {
		NewTestRequest(t, "GET", "/images/avatars/1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/INVALID.jpeg").
			Send().
			ExpectStatus(http.StatusBadRequest)
	})

	t.Run("Get Image", func(t *testing.T) {
		NewTestRequest(t, "GET", "/images/avatars/1/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/md.jpeg").
			Send().
			ExpectStatus(http.StatusOK)
	})

}
