package tools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type contextKey string

const (
	EPOCH_MILLI                              = 1207008000000       // Generic EPOCH (April 1st 2008, Teto b-day!)
	EPOCH_SECONDS                            = EPOCH_MILLI / 1000  // Generic EPOCH in Seconds
	CONTEXT_TIMEOUT                          = 10 * time.Second    // Default Context Timeout
	LIFETIME_OAUTH2_GRANT_TOKEN              = 15 * time.Second    // Lifetime for OAuth2 Grant Token
	LIFETIME_OAUTH2_ACCESS_TOKEN             = 7 * 24 * time.Hour  // Lifetime for OAuth2 Access Token
	LIFETIME_TOKEN_USER_ELEVATION            = 10 * time.Minute    // Lifetime for User Elevation
	LIFETIME_TOKEN_USER_COOKIE               = 30 * 24 * time.Hour // Lifetime for User Cookie
	LIFETIME_TOKEN_EMAIL_PASSCODE            = 15 * time.Minute    // Lifetime for MFA Passcode
	LIFETIME_TOKEN_EMAIL_LOGIN               = 24 * time.Hour      // Lifetime for Verify Login Token
	LIFETIME_TOKEN_EMAIL_VERIFY              = 24 * time.Hour      // Lifetime for Verify Email Token
	LIFETIME_TOKEN_EMAIL_RESET               = 24 * time.Hour      // Lifetime for Password Reset Token
	PASSWORD_HASH_EFFORT                     = 12                  // Password Hashing Effort
	PASSWORD_HISTORY_LIMIT                   = 3                   // Password History Length
	MFA_PASSCODE_LENGTH                      = 6                   // TOTP Passcode String Length (Do Not Change)
	MFA_RECOVERY_LENGTH                      = 8                   // TOTP Recovery Code Length (Do Not Change)
	TOKEN_PREFIX_USER                        = "User"
	TOKEN_PREFIX_BEARER                      = "Bearer"
	SESSION_KEY                   contextKey = "gloopert"
)

var (
	MACHINE_ID                  = EnvString("MACHINE_ID", "0")
	DATABASE_URL                = EnvString("DATABASE_URL", "postgresql://postgres:password@localhost:5432")
	DATABASE_TLS_ENABLED        = EnvString("DATABASE_TLS_ENABLED", "false") == "true"
	DATABASE_TLS_CERT           = EnvString("DATABASE_TLS_CERT", "tls_crt.pem")
	DATABASE_TLS_KEY            = EnvString("DATABASE_TLS_KEY", "tls_key.pem")
	DATABASE_TLS_CA             = EnvString("DATABASE_TLS_CA", "tls_ca.pem")
	EMAIL_PROVIDER              = EnvString("EMAIL_PROVIDER", "none")
	EMAIL_SENDER_NAME           = EnvString("EMAIL_SENDER_NAME", "noreply")
	EMAIL_SENDER_ADDRESS        = EnvString("EMAIL_SENDER_ADDRESS", "noreply@example.org")
	EMAIL_DEFAULT_DISPLAYNAME   = EnvString("EMAIL_DEFAULT_DISPLAYNAME", "User")
	EMAIL_DEFAULT_HOST          = EnvString("EMAIL_DEFAULT_HOST", "https://example.org")
	EMAIL_ENGINE_URL            = EnvString("EMAIL_ENGINE_URL", "http://localhost:8080")
	EMAIL_ENGINE_KEY            = EnvString("EMAIL_ENGINE_KEY", "teto")
	EMAIL_SES_ACCESS_KEY        = EnvString("EMAIL_SES_ACCESS_KEY", "xyz")
	EMAIL_SES_SECRET_KEY        = EnvString("EMAIL_SES_SECRET_KEY", "123")
	EMAIL_SES_REGION            = EnvString("EMAIL_SES_REGION", "unknown")
	EMAIL_SES_CONFIGURATION_SET = EnvString("EMAIL_SES_CONFIGURATION_SET", "unknown")
	STORAGE_PROVIDER            = EnvString("STORAGE_PROVIDER", "none")
	STORAGE_DISK_DIRECTORY      = EnvString("STORAGE_DISK_DIRECTORY", "data")
	STORAGE_DISK_PERMISSIONS    = EnvNumber("STORAGE_DISK_PERMISSIONS", 2760)
	STORAGE_S3_KEY_SECRET_KEY   = EnvString("STORAGE_S3_KEY_SECRET_KEY", "xyz")
	STORAGE_S3_KEY_ACCESS_KEY   = EnvString("STORAGE_S3_KEY_ACCESS_KEY", "123")
	STORAGE_S3_ENDPOINT         = EnvString("STORAGE_S3_ENDPOINT", "bucket.s3.region.host.tld")
	STORAGE_S3_REGION           = EnvString("STORAGE_S3_REGION", "region")
	STORAGE_S3_BUCKET           = EnvString("STORAGE_S3_BUCKET", "bucket")
	RATELIMIT_PROVIDER          = EnvString("RATELIMIT_PROVIDER", "local")
	RATELIMIT_REDIS_URI         = EnvString("RATELIMIT_REDIS_URI", "redis://localhost:6379")
	RATELIMIT_REDIS_TLS_ENABLED = EnvString("RATELIMIT_REDIS_TLS_ENABLED", "false") == "true"
	RATELIMIT_REDIS_TLS_CERT    = EnvString("RATELIMIT_REDIS_TLS_CERT", "tls_crt.pem")
	RATELIMIT_REDIS_TLS_KEY     = EnvString("RATELIMIT_REDIS_TLS_KEY", "tls_key.pem")
	RATELIMIT_REDIS_TLS_CA      = EnvString("RATELIMIT_REDIS_TLS_CA", "tls_ca.pem")
	LOGGER_PROVIDER             = EnvString("LOGGER_PROVIDER", "console")
	HTTP_ADDRESS                = EnvString("HTTP_ADDRESS", "localhost:8080")
	HTTP_SERVE_IMAGES           = EnvString("HTTP_SERVE_IMAGES", "true") == "true"
	HTTP_COOKIE_NAME            = EnvString("HTTP_COOKIE_NAME", "session")
	HTTP_COOKIE_DOMAIN          = EnvString("HTTP_COOKIE_DOMAIN", "")
	HTTP_COOKIE_SECURE          = EnvString("HTTP_COOKIE_SECURE", "false") == "true"
	HTTP_CORS_ORIGINS           = EnvSlice("HTTP_CORS_ORIGINS", ",", []string{"http://localhost:5173"})
	HTTP_IP_HEADERS             = EnvSlice("HTTP_IP_HEADERS", ",", []string{"X-Forwarded-By"})
	HTTP_IP_PROXIES             = EnvSlice("HTTP_IP_PROXIES", ",", []string{"127.0.0.1/8"})
	HTTP_KEY                    = []byte(EnvString("HTTP_KEY", "teto"))
	HTTP_SERVER_TOKEN           = EnvString("HTTP_SERVER_TOKEN", "true") == "true"
	HTTP_TLS_ENABLED            = EnvString("HTTP_TLS_ENABLED", "false") == "true"
	HTTP_TLS_CERT               = EnvString("HTTP_TLS_CERT", "tls_crt.pem")
	HTTP_TLS_KEY                = EnvString("HTTP_TLS_KEY", "tls_key.pem")
	HTTP_TLS_CA                 = EnvString("HTTP_TLS_CA", "tls_ca.pem")
)

// Default Context Timeout
func NewContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), CONTEXT_TIMEOUT)
}

// Create TLS Configuration from Crypto
func NewTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(HTTP_TLS_CERT, HTTP_TLS_KEY)
	if err != nil {
		return nil, err
	}
	caBytes, err := os.ReadFile(HTTP_TLS_CA)
	if err != nil {
		return nil, err
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caBytes) {
		return nil, errors.New("cannot append ca bundle")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
	}, nil
}

// Read String from Environment
func EnvString(field, initial string) string {
	if value := os.Getenv(field); value == "" {
		return initial
	} else {
		return value
	}
}

// Read String from Environment and Parse it as a slice using the given delimiter
func EnvSlice(field, delimiter string, initial []string) []string {
	if value := os.Getenv(field); value == "" {
		return initial
	} else {
		return strings.Split(value, delimiter)
	}
}

// Read String from Environment and Parse it as a number
func EnvNumber(field string, initial int) int {
	if value := os.Getenv(field); value == "" {
		return initial
	} else if number, err := strconv.Atoi(value); err != nil {
		return initial
	} else {
		return number
	}
}
