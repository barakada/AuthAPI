CREATE TABLE IF NOT EXISTS users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email text NOT NULL,
    email_key text NOT NULL UNIQUE,
    password_hash text NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_digest bytea PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_user_expiry ON sessions (user_id, expires_at);
