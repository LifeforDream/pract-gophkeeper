CREATE TABLE users (
    id              varchar(36))        PRIMARY KEY,
    login           varchar(255)        NOT NULL,
    auth_hash       bytea       NOT NULL,
    kdf_salt        bytea       NOT NULL,
    kdf_memory_kib  integer     NOT NULL CHECK (kdf_memory_kib > 0),
    kdf_iterations  integer     NOT NULL CHECK (kdf_iterations > 0),
    kdf_parallelism smallint    NOT NULL CHECK (kdf_parallelism > 0),
    revision        bigint      NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
    CONSTRAINT uq_users_login UNIQUE (login),
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
    CONSTRAINT records_pkey PRIMARY KEY (user_id, id),
    CONSTRAINT uq_records_user_revision UNIQUE (user_id, revision)
);
