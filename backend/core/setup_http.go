package core

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/bakonpancakz/template-auth/routes"
	"github.com/bakonpancakz/template-auth/tools"
)

func SetupHTTP(stop context.Context, await *sync.WaitGroup) {

	// Optimized to prevent malicious attacks but shouldn't
	// really bother devices on slower networks :)

	svr := http.Server{
		Handler:           SetupMux(),
		Addr:              tools.HTTP_ADDRESS,
		MaxHeaderBytes:    4096,
		IdleTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		ReadTimeout:       10 * time.Second,
	}
	if tools.HTTP_TLS_ENABLED {
		tls, err := tools.NewTLSConfig(
			tools.HTTP_TLS_CERT,
			tools.HTTP_TLS_KEY,
			tools.HTTP_TLS_CA,
		)
		if err != nil {
			tools.LoggerHttp.Fatal("Failed to configure TLS", err.Error())
			return
		}
		svr.TLSConfig = tls
	}

	// Shutdown Logic
	await.Add(1)
	go func() {
		defer await.Done()
		<-stop.Done()
		svr.Shutdown(context.Background())
		tools.LoggerHttp.Info("Closed", nil)
	}()

	// Server Startup
	var err error
	tools.LoggerHttp.Info("Ready", map[string]any{"address": svr.Addr})
	if tools.HTTP_TLS_ENABLED {
		err = svr.ListenAndServeTLS("", "")
	} else {
		err = svr.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		tools.LoggerHttp.Fatal("Startup Failed", err.Error())
	}
}

func SetupMux() *http.ServeMux {
	var (
		mux       = http.NewServeMux()
		session   = tools.UseSession
		limitFILE = tools.NewBodyLimit(10 * 1024 * 1024) // 10MB
		limitJSON = tools.NewBodyLimit(10 * 1024)        // 10KB
		rateLogin = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_LOGIN",
			Period: time.Minute,
			Limit:  5,
		})
		rateClientRead = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_CLIENT_READ",
			Period: time.Minute,
			Limit:  100,
		})
		rateClientWrite = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_CLIENT_WRITE",
			Period: time.Minute,
			Limit:  10,
		})
		rateImageWrite = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_IMAGE_WRITE",
			Period: 5 * time.Minute,
			Limit:  3,
		})
		rateImageRead = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_IMAGE_READ",
			Period: time.Minute,
			Limit:  100,
		})
		rateServerWrite = tools.NewRatelimit(&tools.RatelimitOptions{
			Bucket: "RATE_SERVER_WRITE",
			Period: time.Minute,
			Limit:  1000,
		})
	)

	// Login Routes
	mux.Handle("/auth/login", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Auth_Login, rateLogin, limitJSON),
	})
	mux.Handle("/auth/signup", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Auth_Signup, rateLogin, limitJSON),
	})
	mux.Handle("/auth/logout", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Auth_Logout, rateLogin, limitJSON, session),
	})
	mux.Handle("/auth/password-reset", tools.MethodHandler{
		http.MethodPost:  tools.Chain(routes.POST_Auth_ResetPassword, rateLogin, limitJSON),
		http.MethodPatch: tools.Chain(routes.PATCH_Auth_ResetPassword, rateLogin, limitJSON),
	})
	mux.Handle("/auth/verify-login", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Auth_VerifyLogin, rateLogin, limitJSON),
	})
	mux.Handle("/auth/verify-email", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Auth_VerifyEmail, rateLogin, limitJSON),
	})

	// oAuth2
	mux.Handle("/oauth2/authorize", tools.MethodHandler{
		http.MethodGet:  tools.Chain(routes.GET_OAuth2_Authorize, rateClientRead, session),
		http.MethodPost: tools.Chain(routes.POST_OAuth2_Authorize, rateClientWrite, session),
	})
	mux.Handle("/oauth2/token", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_OAuth2_Token, rateServerWrite),
	})
	mux.Handle("/oauth2/token/revoke", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_OAuth2_Token_Revoke, rateServerWrite),
	})

	// User
	mux.Handle("/users/@me", tools.MethodHandler{
		http.MethodGet:    tools.Chain(routes.GET_Users_Me, rateClientRead, session),
		http.MethodPatch:  tools.Chain(routes.PATCH_Users_Me, rateClientWrite, limitJSON, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me, rateClientWrite, session),
	})
	mux.Handle("/users/@me/avatar", tools.MethodHandler{
		http.MethodPut:    tools.Chain(routes.PUT_Users_Me_Avatar, rateImageWrite, limitFILE, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Avatar, rateClientWrite, session),
	})
	mux.Handle("/users/@me/banner", tools.MethodHandler{
		http.MethodPut:    tools.Chain(routes.PUT_Users_Me_Banner, rateImageWrite, limitFILE, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Banner, rateClientWrite, session),
	})

	// User Applications
	mux.Handle("/users/@me/applications", tools.MethodHandler{
		http.MethodGet:  tools.Chain(routes.GET_Users_Me_Applications, rateClientRead, session),
		http.MethodPost: tools.Chain(routes.POST_Users_Me_Applications, rateClientWrite, session),
	})
	mux.Handle("/users/@me/applications/{id}", tools.MethodHandler{
		http.MethodPatch:  tools.Chain(routes.PATCH_Users_Me_Applications_ID, rateClientWrite, limitJSON, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Applications_ID, rateClientWrite, session),
	})
	mux.Handle("/users/@me/applications/{id}/icon", tools.MethodHandler{
		http.MethodPut:    tools.Chain(routes.PUT_Users_Me_Applications_ID_Icon, rateImageWrite, limitFILE, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Applications_ID_Icon, rateClientWrite, session),
	})
	mux.Handle("/users/@me/applications/{id}/reset", tools.MethodHandler{
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Applications_ID_Reset, rateClientWrite, session),
	})

	// User Connections
	mux.Handle("/users/@me/connections", tools.MethodHandler{
		http.MethodGet: tools.Chain(routes.GET_Users_Me_Connections, rateClientRead, session),
	})
	mux.Handle("/users/@me/connections/{id}", tools.MethodHandler{
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Connections_ID, rateClientWrite, session),
	})

	// User Sessions
	mux.Handle("/users/@me/security/sessions", tools.MethodHandler{
		http.MethodGet: tools.Chain(routes.GET_Users_Me_Security_Sessions, rateClientRead, session),
	})
	mux.Handle("/users/@me/security/sessions/{id}", tools.MethodHandler{
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Security_Sessions_ID, rateClientWrite, session),
	})

	// User MFA
	mux.Handle("/users/@me/security/mfa/setup", tools.MethodHandler{
		http.MethodGet:    tools.Chain(routes.GET_Users_Me_Security_MFA_Setup, rateClientWrite, session),
		http.MethodPost:   tools.Chain(routes.POST_Users_Me_Security_MFA_Setup, rateClientWrite, limitJSON, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Security_MFA_Setup, rateClientWrite, session),
	})
	mux.Handle("/users/@me/security/mfa/codes", tools.MethodHandler{
		http.MethodGet:    tools.Chain(routes.GET_Users_Me_Security_MFA_Codes, rateClientRead, session),
		http.MethodDelete: tools.Chain(routes.DELETE_Users_Me_Security_MFA_Codes, rateClientWrite, session),
	})

	// User Security
	mux.Handle("/users/@me/security/escalate", tools.MethodHandler{
		http.MethodPost: tools.Chain(routes.POST_Users_Me_Security_Escalate, rateClientWrite, limitJSON, session),
	})
	mux.Handle("/users/@me/security/password", tools.MethodHandler{
		http.MethodPatch: tools.Chain(routes.PATCH_Users_Me_Security_Password, rateClientWrite, limitJSON, session),
	})
	mux.Handle("/users/@me/security/email", tools.MethodHandler{
		http.MethodPost:  tools.Chain(routes.POST_Users_Me_Security_Email, rateClientWrite, session),
		http.MethodPatch: tools.Chain(routes.PATCH_Users_Me_Security_Email, rateClientWrite, limitJSON, session),
	})

	// Image Endpoints
	if tools.HTTP_SERVE_IMAGES {
		mux.Handle("/images/{category}/{id}/{hash}/{filename}", tools.MethodHandler{
			http.MethodGet: tools.Chain(routes.GET_Images_Category_ID_Hash_Filename, rateImageRead),
		})
	}

	// Default 404 Handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tools.SendClientError(w, r, tools.ERROR_GENERIC_NOT_FOUND)
	})

	return mux
}
