DO $MAIN$
DECLARE _VERSION INTEGER;
BEGIN
    /*
     * FETCH SCHEMA VERSION
     *  Migration information is stored in the database using this nifty bit of
     *  logic. Please note that there is no rollback procedure so make sure you
     *  test as much as possible on your dev machine, thanks. @_@
     */
	IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'kvs' AND table_schema = 'public') THEN
		CREATE TABLE kvs (
			key		TEXT NOT NULL UNIQUE,
			value 	TEXT NOT NULL
		);
    END IF;

    SELECT value::INTEGER INTO _VERSION FROM kvs WHERE key = 'version';
    IF (SELECT _VERSION IS NULL) THEN
        INSERT INTO kvs VALUES ('updated', CURRENT_TIMESTAMP::TEXT);
        INSERT INTO kvs VALUES ('version', 0);
        _VERSION := 0;
    END IF;

    /*
     * Version:     1.0.0
     * Name:        Authentication
     * Description: Initialize Database for Authentication Framework
     */
	IF (SELECT _VERSION < 1) THEN
        _VERSION := 1;
		RAISE NOTICE 'Upgrading to Version %', _VERSION;

        -- INITIALIZATION --
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'user_backend') THEN
            DROP OWNED BY user_backend CASCADE;
            DROP ROLE user_backend;
        END IF;
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'user_profiles') THEN
            DROP OWNED BY user_profiles CASCADE;
            DROP ROLE user_profiles;
        END IF;
        DROP SCHEMA IF EXISTS auth CASCADE;
        CREATE SCHEMA auth;

        -- TABLES --
        CREATE TABLE auth.users (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Account ID
            created             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Created At
            updated             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Updated At
            email_address       TEXT            NOT NULL UNIQUE,                            -- User Email Address
            email_verified      BOOLEAN         NOT NULL DEFAULT FALSE,                     -- Email Verified?
            ip_address          TEXT            NOT NULL DEFAULT '',                        -- New Login IP Address
            mfa_enabled         BOOLEAN         NOT NULL DEFAULT FALSE,                     -- MFA Enabled?
            mfa_secret          TEXT,                                                       -- MFA Secret Key
            mfa_codes           TEXT[]          NOT NULL DEFAULT '{}',                      -- MFA Recovery Codes
            mfa_codes_used      INT             NOT NULL DEFAULT 0,                         -- MFA Exhausted Recovery Code Bitfield
            password_hash       TEXT,                                                       -- Active Password Hash
            password_history    TEXT[]          NOT NULL DEFAULT '{}',                      -- Past Password Hashes
            token_verify        TEXT            UNIQUE,                                     -- Verify Email Token
            token_verify_eat    TIMESTAMP,                                                  -- Verify Email Token Expires At
            token_login         TEXT            UNIQUE,                                     -- New Login Token
            token_login_data    TEXT,                                                       -- New Login Token Arbitrary Data
            token_login_eat     TIMESTAMP,                                                  -- New Login Token Expires At
            token_reset         TEXT            UNIQUE,                                     -- Password Reset Token
            token_reset_eat     TIMESTAMP,                                                  -- Password Reset Token Expires At
            token_passcode      TEXT,                                                       -- Random Escalation Code
            token_passcode_eat  TIMESTAMP                                                   -- Random Escalation Code Expires At
        );

        CREATE TABLE IF NOT EXISTS auth.profiles (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Account ID
            created             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Created At
            updated             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Updated At
            username            TEXT            NOT NULL UNIQUE,                            -- Username
            displayname         TEXT            NOT NULL,                                   -- Nickname
            subtitle            TEXT,                                                       -- Pronouns
            biography           TEXT,                                                       -- Biography
            avatar_hash         TEXT,                                                       -- Avatar Image Hash
            banner_hash         TEXT,                                                       -- Banner Image Hash
            accent_banner       INT,                                                        -- Banner Color
            accent_border       INT,                                                        -- Border Color
            accent_background   INT,                                                        -- Background Color
            FOREIGN KEY (id) REFERENCES auth.users(id) ON DELETE CASCADE
        );

        CREATE TABLE auth.sessions (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Session ID
            created             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Created At
            updated             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Updated At
            user_id             BIGINT          NOT NULL,                                   -- Relevant User ID
            revoked             BOOLEAN         NOT NULL DEFAULT FALSE,                     -- Session Revoked?
            token               TEXT            UNIQUE,                                     -- Session Token
            elevated_until      INT             NOT NULL DEFAULT 0,                         -- Elevated Until UNIX Timestamp
            device_ip_address   TEXT            NOT NULL,                                   -- IP Address of Device
            device_user_agent   TEXT            NOT NULL,                                   -- User Agent of Device
            FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
        );

        CREATE TABLE auth.applications (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Application ID
            created             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Created At
            updated             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Updated At
            user_id             BIGINT          NOT NULL,                                   -- Relevant User ID
            name                TEXT            NOT NULL,                                   -- Name
            description         TEXT,                                                       -- Description
            icon_hash           TEXT,                                                       -- Icon Hash
            auth_secret         TEXT            NOT NULL,                                   -- oAuth2 Client Secret
            auth_redirects      TEXT[]          NOT NULL DEFAULT '{}',                      -- oAuth2 Redirect Whitelist
            FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
        );

        CREATE TABLE auth.connections (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Connection ID
            created             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Created At
            updated             TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Refreshed At
            user_id             BIGINT          NOT NULL,                                   -- Relevant User ID
            application_id      BIGINT          NOT NULL,                                   -- Relevant Application ID
            revoked             BOOLEAN         NOT NULL DEFAULT FALSE,                     -- Connection Revoked?
            scopes              INT             NOT NULL DEFAULT 0,                         -- Connection Scopes
            token_access        TEXT            UNIQUE,                                     -- Connection Access Token
            token_expires       TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP,         -- Connection Access Token Expires At
            token_refresh       TEXT            UNIQUE,                                     -- Connection Refresh Token
            CONSTRAINT unique_connections UNIQUE (user_id, application_id),
            FOREIGN KEY (user_id)        REFERENCES auth.users(id)        ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES auth.applications(id) ON DELETE CASCADE
        );

        CREATE UNLOGGED TABLE auth.grants (
            id                  BIGINT          NOT NULL PRIMARY KEY,                       -- Grant ID
            expires             TIMESTAMP       NOT NULL,                                   -- Expires At
            user_id             BIGINT          NOT NULL,                                   -- Relevant User ID
            application_id      BIGINT          NOT NULL,                                   -- Relevant Application ID
            redirect_uri        TEXT            NOT NULL,                                   -- Requested Redirect URI
            scopes              INT             NOT NULL,                                   -- Requested Scopes
            code                TEXT            NOT NULL UNIQUE,                            -- Grant Code
            FOREIGN KEY (user_id)        REFERENCES auth.users(id)        ON DELETE CASCADE,
            FOREIGN KEY (application_id) REFERENCES auth.applications(id) ON DELETE CASCADE
        );

        -- USERS --
        -- Used by the auth framework full to read and write sensitive fields
        CREATE ROLE user_backend LOGIN NOINHERIT;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.profiles       TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.users          TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.profiles       TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.sessions       TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.applications   TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.connections    TO user_backend;
        GRANT SELECT, INSERT, UPDATE, DELETE ON auth.grants         TO user_backend;

        -- This user is intended to provide read access to user profiles to
        -- application backends that may require it.
        CREATE ROLE user_profiles LOGIN NOINHERIT;
        GRANT SELECT ON auth.profiles TO user_profiles;
    END IF;

    /*
     * HOUSEKEEPING
     *  Uses the "pg_cron" extension to enable automated maintenance without
     *  requiring the use of an external service, see installation guide here:
     *  https://github.com/citusdata/pg_cron#installing-pg_cron
     *
     *  NOTE: This extension is not required while in development but will cause
     *  issues in production as memory usage will climb indefinitely.
     */
    IF NOT EXISTS (SELECT FROM pg_available_extensions WHERE name = 'pg_cron') THEN
        RAISE WARNING 'Extension "pg_cron" is not installed, disabling cron scheduling.';
    ELSE
        CREATE EXTENSION IF NOT EXISTS pg_cron;
        CREATE OR REPLACE PROCEDURE pgx_reschedule (
            _SCHEDULE 	TEXT,
            _NAME 		TEXT,
            _COMMAND 	TEXT
        )
        LANGUAGE plpgsql SECURITY DEFINER AS $$
            BEGIN
                IF EXISTS (SELECT FROM cron.job WHERE jobname = _NAME) THEN
                    PERFORM cron.unschedule(_NAME);
                END IF;
                PERFORM cron.schedule(_NAME, _SCHEDULE, _COMMAND);
                RAISE NOTICE 'Scheduled "%" (%)', _NAME, _SCHEDULE;
            END;
        $$;
        CALL pgx_reschedule('0 4 * * *',   'Delete Revoked Sessions', $$ DELETE FROM auth.sessions WHERE revoked = TRUE $$);
        CALL pgx_reschedule('0 4 * * *',   'Cleanup Grants',          $$ TRUNCATE auth.grants                           $$);
    END IF;

    /*
     * GLOBALS
     *  Use this function to quickly store some variables which can later be
     *  retreived by your applications. Sensitive information should NOT kept
     *  here as the table is public to all database users.
     */
    CREATE OR REPLACE PROCEDURE pgx_global (
        _KEY 		TEXT,
        _VALUE 	    TEXT
    )
    LANGUAGE plpgsql SECURITY DEFINER AS $$
        BEGIN
            INSERT INTO kvs (key, value) VALUES (_KEY, _VALUE)
            ON CONFLICT (key) DO UPDATE SET value = _VALUE;
            RAISE NOTICE 'Set Variable "%" to "%"', _KEY, _VALUE;
        END;
    $$;

    /*
     * UPDATE SCHEMA VERSION
     *  Disabled in development to make iterative changes less annoying. Use the
     *  following query to enter production mode and make changes permanent:
     *  `INSERT INTO kvs (key, value) VALUES ('production, 'true');`
     */
    IF EXISTS (SELECT FROM kvs WHERE key = 'production') THEN
	    UPDATE kvs SET value = _VERSION                WHERE key = 'version';
	    UPDATE kvs SET value = CURRENT_TIMESTAMP::TEXT WHERE key = 'updated';
	END IF;

END $MAIN$;
