-- Registered users. The private key never reaches the backend; only the
-- libp2p public key (protobuf-encoded) and the Peer ID derived from it.
CREATE TABLE users (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email             TEXT        NOT NULL,
    email_verified_at TIMESTAMPTZ NOT NULL,
    username          TEXT        NOT NULL,
    password_hash     TEXT        NOT NULL,
    peer_id           TEXT        NOT NULL,
    public_key        BYTEA       NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Case-insensitive global uniqueness: "Rahul" and "rahul" are the same name.
CREATE UNIQUE INDEX users_username_lower_key ON users (lower(username));
CREATE UNIQUE INDEX users_email_lower_key    ON users (lower(email));
CREATE UNIQUE INDEX users_peer_id_key        ON users (peer_id);

-- Pending email OTPs. Only an HMAC of the code is stored.
CREATE TABLE email_otps (
    email        TEXT        PRIMARY KEY,
    code_hash    BYTEA       NOT NULL,
    attempts     INT         NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ NOT NULL,
    last_sent_at TIMESTAMPTZ NOT NULL
);

-- Short-lived tokens proving an email was verified, consumed on registration.
CREATE TABLE registration_sessions (
    token_hash BYTEA       PRIMARY KEY,
    email      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX registration_sessions_expires_at_idx ON registration_sessions (expires_at);
