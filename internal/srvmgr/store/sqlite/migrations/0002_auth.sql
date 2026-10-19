CREATE TABLE users (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'readonly')),
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL
);

-- token_hash is SHA-256 of the cookie token: a stolen database file does
-- not give live sessions.
CREATE TABLE sessions (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	token_hash   BLOB NOT NULL UNIQUE,
	user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL,
	expires_at   INTEGER NOT NULL,
	revoked_at   INTEGER,
	ip           TEXT NOT NULL DEFAULT '',
	user_agent   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user ON sessions (user_id);
