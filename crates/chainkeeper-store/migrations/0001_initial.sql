-- Chainkeeper index schema, version 1.
--
-- The index is disposable: every row can be rebuilt from canonical records.
-- journal_mode=WAL, synchronous=NORMAL, and foreign_keys=ON are applied to the
-- connection before this migration runs, because they are connection scoped
-- and journal mode cannot change inside a transaction.

PRAGMA foreign_keys = ON;

CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE certificates (
    id INTEGER PRIMARY KEY,
    serial TEXT NOT NULL UNIQUE,
    subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    profile TEXT NOT NULL,
    authority TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    status TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    path TEXT NOT NULL,
    sans_json TEXT NOT NULL,
    email TEXT,
    eku_json TEXT NOT NULL,
    key_usage_json TEXT NOT NULL,
    revoked_at TEXT,
    revocation_reason TEXT,
    replaces TEXT
);

CREATE INDEX certificates_status_idx ON certificates (status);
CREATE INDEX certificates_profile_idx ON certificates (profile);
CREATE INDEX certificates_authority_idx ON certificates (authority);
CREATE INDEX certificates_expires_at_idx ON certificates (expires_at);
CREATE INDEX certificates_subject_idx ON certificates (subject);
CREATE INDEX certificates_email_idx ON certificates (email);

CREATE TABLE revocations (
    id INTEGER PRIMARY KEY,
    certificate_id INTEGER NOT NULL REFERENCES certificates (id),
    serial TEXT NOT NULL UNIQUE,
    authority TEXT NOT NULL,
    reason TEXT NOT NULL,
    comment TEXT NOT NULL DEFAULT '',
    revoked_at TEXT NOT NULL,
    crl_number INTEGER
);

CREATE INDEX revocations_authority_idx ON revocations (authority);

CREATE TABLE intermediates (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    parent TEXT,
    algorithm TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    path TEXT NOT NULL
);

CREATE TABLE profiles (
    name TEXT PRIMARY KEY,
    authority TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    validity_days INTEGER NOT NULL,
    yaml_sha256 TEXT NOT NULL
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    seq INTEGER NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    summary TEXT NOT NULL,
    path TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT 'null'
);

CREATE INDEX audit_events_action_idx ON audit_events (action);
CREATE INDEX audit_events_object_idx ON audit_events (object_type, object_id);

CREATE TABLE crls (
    authority TEXT PRIMARY KEY,
    crl_number INTEGER NOT NULL,
    this_update TEXT NOT NULL,
    next_update TEXT NOT NULL,
    revoked_count INTEGER NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL
);

-- Standalone FTS index maintained by the indexer, not by triggers.
CREATE VIRTUAL TABLE certificates_fts USING fts5 (
    serial,
    subject,
    sans,
    email,
    profile,
    tokenize = 'unicode61 remove_diacritics 2'
);
