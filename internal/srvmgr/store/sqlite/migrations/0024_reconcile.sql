-- Reconciliation of server state (P4-06). A config changed outside HyRoute
-- and accepted by the admin becomes a revision with source 'external'.
-- SQLite cannot change a CHECK constraint, so server_configs is rebuilt.
CREATE TABLE server_configs_new (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id     INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	revision      INTEGER NOT NULL,
	config        BLOB NOT NULL,
	sha256        TEXT NOT NULL,
	meta          TEXT NOT NULL DEFAULT '{}',
	source        TEXT NOT NULL CHECK (source IN ('deploy', 'import', 'edit', 'rollback', 'rotate', 'cascade', 'geo', 'external')),
	from_revision INTEGER,
	job_id        INTEGER REFERENCES jobs (id) ON DELETE SET NULL,
	created_by    INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at    INTEGER NOT NULL,
	UNIQUE (server_id, revision)
);
INSERT INTO server_configs_new (id, server_id, revision, config, sha256, meta, source, from_revision, job_id, created_by, created_at)
	SELECT id, server_id, revision, config, sha256, meta, source, from_revision, job_id, created_by, created_at FROM server_configs;
DROP TABLE server_configs;
ALTER TABLE server_configs_new RENAME TO server_configs;

-- What HyRoute installed or found: the SHA-256 of the binary and the
-- fingerprint of the unit ('' for installations recorded before: not
-- compared until a job records them).
ALTER TABLE installations ADD COLUMN binary_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE installations ADD COLUMN unit_sha256 TEXT NOT NULL DEFAULT '';
-- The fingerprint of a link's unit, recorded by the link job.
ALTER TABLE chain_links ADD COLUMN unit_sha256 TEXT NOT NULL DEFAULT '';

-- The latest reconciliation of each server: what it compared (checked),
-- what had nothing recorded (skipped), the differences (items, JSON
-- without secrets) and the config found on the server while it differs
-- from the revision, sealed (context server/<id>/drift/config).
-- attention_at: when the round made the server needs_attention; reverts:
-- the jobs queued from it since then.
CREATE TABLE drift (
	server_id    INTEGER PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
	at           INTEGER NOT NULL,
	error        TEXT NOT NULL DEFAULT '',
	checked      TEXT NOT NULL DEFAULT '[]',
	skipped      TEXT NOT NULL DEFAULT '[]',
	items        TEXT NOT NULL DEFAULT '[]',
	config       BLOB,
	attention_at INTEGER NOT NULL DEFAULT 0,
	reverts      TEXT NOT NULL DEFAULT '[]'
);
