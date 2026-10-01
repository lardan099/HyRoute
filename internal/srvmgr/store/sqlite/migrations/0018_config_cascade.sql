-- Config revisions can come from a cascade link (P3-02): source
-- 'cascade' (the link's user on the exit, its outbound on the entry).
-- SQLite cannot change a CHECK constraint, so the table is rebuilt.
CREATE TABLE server_configs_new (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id     INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	revision      INTEGER NOT NULL,
	config        BLOB NOT NULL,
	sha256        TEXT NOT NULL,
	meta          TEXT NOT NULL DEFAULT '{}',
	source        TEXT NOT NULL CHECK (source IN ('deploy', 'import', 'edit', 'rollback', 'rotate', 'cascade')),
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
