-- Hysteria config revisions of a server: what the controller installed or
-- found there. The YAML holds passwords, so it is sealed (secrets.Keyring,
-- context server/<id>/config/<revision>); meta is the non-secret summary
-- (version, listen, TLS mode, certificate pin, SNI, obfs type).
CREATE TABLE server_configs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	server_id  INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	revision   INTEGER NOT NULL,
	config     BLOB NOT NULL,
	sha256     TEXT NOT NULL,
	meta       TEXT NOT NULL DEFAULT '{}',
	source     TEXT NOT NULL CHECK (source IN ('deploy', 'import', 'edit')),
	job_id     INTEGER REFERENCES jobs (id) ON DELETE SET NULL,
	created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at INTEGER NOT NULL,
	UNIQUE (server_id, revision)
);
