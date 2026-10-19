-- Controller-wide key/value settings (no secrets: those live in sealed
-- columns of their own tables).
CREATE TABLE settings (
	key        TEXT PRIMARY KEY,
	value      TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);

-- Who did what: logins, deployments, host key trust, revealed secrets.
CREATE TABLE audit_log (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	ts      INTEGER NOT NULL,
	user_id INTEGER,
	action  TEXT NOT NULL,
	target  TEXT NOT NULL DEFAULT '',
	details TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_ts ON audit_log (ts);
