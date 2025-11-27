<!-- omit from toc -->
# 📦 @template-auth/backend

The authentication backend requires **Go 1.25.2 or newer**, a local disk for
temporary files, and a **PostgreSQL** instance to initialize properly.

- [➕ Contributing](#-contributing)
  - [🧪 Debugging / Testing](#-debugging--testing)
  - [🔰 Codebase Overview](#-codebase-overview)
- [🆙 Running Locally](#-running-locally)
  - [🔧 Configuration](#-configuration)

<br>

# ➕ Contributing
This project was originally developed for personal use, so most features I
personally needed are already implemented.

However, contributions are still welcome in the following areas:

- **Bug Fixes**

  Although testing catches most logical issues, occasionally an edge case may
  be found. Contributions that fix overlooked issues are appreciated!

- **Service Providers**

  Contributions that expand the list of supported email, rate-limit, storage,
  and logging providers are welcome.
  Please note that I aim to keep dependencies minimal, so try to keep
  implementations as lean as possible.

- **Optimizations**

  Improvements to database queries, memory usage, and startup time are all
  appreciated.

- **Extended Customization**

  Many values have been hardcoded for personal preference.
  If you need a custom value, consider modifying the `util_configuration.go`
  file, setting the default to the original value for compatibility.

<br>

## 🧪 Debugging / Testing
Running `go test ./...` currently requires a live PostgreSQL instance, as
no mocks have been implemented for the database service yet.

Additional debug commands are available below for development and testing.
They override the default startup flow and perform a single operation before
exiting:

- `debug_database_apply_schema`
  Applies the embedded database schema.
  Additional configuration for production use is required regarding user
  authentication and versioning.

- `debug_email_render_template`
  Renders embedded email templates using dummy literals into the `dist` directory.
  Useful for previewing and customizing email templates.

<br>

## 🔰 Codebase Overview
The project is organized into several packages, each handling a specific layer
of the backend. This section gives a quick rundown of what lives where.

```ini
.
|__ /core
|   |__ setup_http.go                   # HTTP Server and Mux
|   |__ debug_database_apply_schema.go  # Debug command: apply embedded schema
|   |__ debug_email_render_templates.go # Debug command: render email templates
|
|__ /include
|   |__ schema.sql                      # PostgreSQL schema
|   |__ /archives
|   |   |__ geolocation.kani.gz         # Embedded geolocation data
|   |__ /templates
|       |__ **/*.html                   # Embedded email templates
|
|__ /routes
|   |__ {METHOD}_{Path}.go              # HTTP route handlers for REST API
|                                       # e.g. POST_Auth_Login.go, GET_Users_Me.go
|__ /tests
|   |__ routes_*.go                     # Tests for route handlers
|   |__ tools_*.go                      # Tests for tools functions
|   |__ testing_*.go                    # Shared test helpers and initializers
|
|__ /tools
    |__ api_body.go                     # Body validators and parsers
    |__ api_errors.go                   # API error handling and response writers
    |__ api_getters.go                  # Request context helpers
    |__ api_middleware.go               # HTTP middleware
    |__ api_scopes.go                   # OAuth2 scopes and permission checks
    |
    |__ provider_email_*.go             # Email providers (SES, EmailEngine, None)
    |__ provider_logger_*.go            # Logging provider(s)
    |__ provider_ratelimit_*.go         # Rate limit providers (Local, Redis)
    |__ provider_storage_*.go           # Storage providers (Disk, S3, None)
    |__ service_database_types.go       # Database type definitions
    |__ service_*.go                    # Core backend service logic
    |
    |__ util_*.go                       # Shared utilities (AWS, Validation, etc.)
```
<br>

# 🆙 Running Locally
The server can be started locally via `go run main.go` but will crash unless
the environment variable `DATABASE_URL` points to an active database with the
schema applied.

> **TIP:** You can apply the database schema to via the included
> [debug commands](#-debugging--testing)

<br>

## 🔧 Configuration
The backend is configured exclusively via **environment variables**.
The table below includes all configurable values:

| Variable                    | Description                                                                                                     |
| --------------------------- | --------------------------------------------------------------------------------------------------------------- |
| MACHINE_ID                  | Machine ID for Snowflake generation, value must be less than `1024`                                             |
| DATABASE_URL                | The URI of the PostgreSQL instance                                                                              |
| DATABASE_TLS_ENABLED        | Enable TLS? Set value to `true` to enable                                                                       |
| DATABASE_TLS_CERT           | Path to SSL Certificate                                                                                         |
| DATABASE_TLS_KEY            | Path to SSL Key                                                                                                 |
| DATABASE_TLS_CA             | Path to SSL Certificate Bundle                                                                                  |
| EMAIL_PROVIDER              | Email Provider to use, allowed values are: `ses`, `emailengine`, `none`                                         |
| EMAIL_SENDER_NAME           | Displayname to send emails as `(e.g. noreply)`                                                                  |
| EMAIL_SENDER_ADDRESS        | Address to send emails as `(e.g. noreply@example.org)`                                                          |
| EMAIL_DEFAULT_DISPLAYNAME   | Displayname to use by when the actual value couldn't be fetched, defaults to `User`                             |
| EMAIL_DEFAULT_HOST          | The base URL to where the frontend is hosted `(e.g. https://example.org)`                                       |
| EMAIL_ENGINE_URL            | The URL to the [EmailEngine](https://github.com/bakonpancakz/emailengine) instance                              |
| EMAIL_ENGINE_KEY            | The Key to the [EmailEngine](https://github.com/bakonpancakz/emailengine) instance                              |
| EMAIL_SES_ACCESS_KEY        | The Access Key for requests to SES                                                                              |
| EMAIL_SES_SECRET_KEY        | The Secret Key for requests to SES                                                                              |
| EMAIL_SES_REGION            | The Region for Requests to SES                                                                                  |
| EMAIL_SES_CONFIGURATION_SET | The Configuration Set to use for SES                                                                            |
| STORAGE_PROVIDER            | Storage Provider to use, allowed values are: `s3`, `disk`, `none`                                               |
| STORAGE_DISK_DIRECTORY      | The directory to store user content, defaults to `data`                                                         |
| STORAGE_DISK_PERMISSIONS    | The default permissions for creating a file, defaults to `2760`                                                 |
| STORAGE_S3_KEY_SECRET_KEY   | The Access Key for requests to S3                                                                               |
| STORAGE_S3_KEY_ACCESS_KEY   | The Secret Key for requests to S3                                                                               |
| STORAGE_S3_ENDPOINT         | The Endpoint to S3 API `(e.g. https://bucket.s3.region.host.tld)`                                               |
| STORAGE_S3_REGION           | The Region for requests to S3                                                                                   |
| STORAGE_S3_BUCKET           | The Bucket for requests to S3                                                                                   |
| RATELIMIT_PROVIDER          | Ratelimit Provider to use, allowed values are `redis`, `local`, `none`                                          |
| RATELIMIT_REDIS_URI         | The URI to the Redis Database Instance                                                                          |
| RATELIMIT_REDIS_TLS_ENABLED | Enable TLS? Set value to `true` to enable                                                                       |
| RATELIMIT_REDIS_TLS_CERT    | Path to SSL Certificate                                                                                         |
| RATELIMIT_REDIS_TLS_KEY     | Path to SSL Key                                                                                                 |
| RATELIMIT_REDIS_TLS_CA      | Path to SSL Certificate Bundle                                                                                  |
| LOGGER_PROVIDER             | Logger Provider to use, allowed values are `console`                                                            |
| HTTP_ADDRESS                | Address to listen to HTTP Requests on                                                                           |
| HTTP_SERVE_IMAGES           | Enable Image Endpoints (e.g. `/images/{category}}/{id}/{hash}/{size}.jpg`), change value from `true` to disable |
| HTTP_COOKIE_NAME            | Name for session cookies                                                                                        |
| HTTP_COOKIE_DOMAIN          | Domain to use for cookies                                                                                       |
| HTTP_COOKIE_SECURE          | Require HTTPS for cookies? Set value to `true` to enable                                                        |
| HTTP_CORS_ORIGINS           | Allowed origins for CORS headers delimited with commas, defaults to `http://localhost:8080`                     |
| HTTP_IP_HEADERS             | Trusted headers from reverse proxy delimited with commas, defaults to `X-Forwarded-By`                          |
| HTTP_IP_PROXIES             | Trusted reverse proxy ranges in CIDR notation, defaults to `127.0.0.1/8`                                        |
| HTTP_KEY                    | They key to use for signed strings, do not expose. Will cause server to exit in production mode.                |
| HTTP_SERVER_TOKEN           | Disable branding via inclusio of server header, change value from `true` to disable                             |
| HTTP_TLS_ENABLED            | Enable TLS? Set value to `true` to enable                                                                       |
| HTTP_TLS_CERT               | Path to SSL Certificate                                                                                         |
| HTTP_TLS_KEY                | Path to SSL Key                                                                                                 |
| HTTP_TLS_CA                 | Path to SSL Certificate Bundle                                                                                  |
