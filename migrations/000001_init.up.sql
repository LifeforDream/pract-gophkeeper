CREATE TABLE users (
    id              text        PRIMARY KEY,
    login           text        NOT NULL UNIQUE,
    auth_hash       bytea       NOT NULL,
    kdf_salt        bytea       NOT NULL,
    kdf_memory_kib  integer     NOT NULL CHECK (kdf_memory_kib > 0),
    kdf_iterations  integer     NOT NULL CHECK (kdf_iterations > 0),
    kdf_parallelism smallint    NOT NULL CHECK (kdf_parallelism > 0),
    revision        bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE records (
    user_id      text        NOT NULL REFERENCES users (id),
    id           text        NOT NULL,
    version      bigint      NOT NULL CHECK (version > 0),
    revision     bigint      NOT NULL,
    deleted      boolean     NOT NULL DEFAULT false,
    header       bytea       NOT NULL,
    header_nonce bytea       NOT NULL,
    body         bytea       NOT NULL,
    body_nonce   bytea       NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, id),
    UNIQUE (user_id, revision)
);

CREATE INDEX records_user_revision_idx ON records (user_id, revision);
