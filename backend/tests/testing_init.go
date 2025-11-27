package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"

	"github.com/bakonpancakz/template-auth/core"
	"github.com/bakonpancakz/template-auth/tools"
)

var (
	HTTP_SERVER *httptest.Server
	HTTP_CLIENT *http.Client
)

func init() {
	// Startup Mock Services
	tools.EMAIL_PROVIDER = "test"
	tools.STORAGE_PROVIDER = "test"
	tools.RATELIMIT_PROVIDER = "test"
	tools.LOGGER_PROVIDER = "test"

	var stopCtx = context.TODO()
	var stopWg sync.WaitGroup
	var syncWg sync.WaitGroup
	for _, fn := range []func(stop context.Context, await *sync.WaitGroup){
		tools.SetupLogger,
		tools.SetupDatabase,
		tools.SetupGeolocation,
		tools.SetupEmailProvider,
		tools.SetupRatelimitProvider,
		tools.SetupStorageProvider,
	} {
		syncWg.Add(1)
		go func() {
			defer syncWg.Done()
			fn(stopCtx, &stopWg)
		}()
	}
	syncWg.Wait()
	HTTP_SERVER = httptest.NewServer(core.SetupMux())
	HTTP_CLIENT = HTTP_SERVER.Client()
	HTTP_CLIENT.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Prevent Client from Accessing Internet on some Endpoints
		return http.ErrUseLastResponse
	}

}
