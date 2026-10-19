CREATE TABLE jobs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	kind          TEXT NOT NULL,
	server_id     INTEGER REFERENCES servers (id) ON DELETE SET NULL,
	state         TEXT NOT NULL,
	current_step  TEXT NOT NULL DEFAULT '',
	params        TEXT NOT NULL DEFAULT '{}', -- JSON, no secrets
	data          TEXT NOT NULL DEFAULT '{}', -- JSON map, no secrets
	secret        BLOB,                       -- sealed JSON (secrets.Keyring, context job/<id>/secret)
	attempt       INTEGER NOT NULL DEFAULT 1,
	error_message TEXT NOT NULL DEFAULT '',
	error_details TEXT NOT NULL DEFAULT '',
	created_by    INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at    INTEGER NOT NULL,
	started_at    INTEGER NOT NULL DEFAULT 0,
	finished_at   INTEGER NOT NULL DEFAULT 0,
	lease_owner   TEXT NOT NULL DEFAULT '',
	lease_until   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX jobs_server ON jobs (server_id, id);
CREATE INDEX jobs_state ON jobs (state);

CREATE TABLE job_steps (
	job_id      INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
	idx         INTEGER NOT NULL,
	name        TEXT NOT NULL,
	phase       TEXT NOT NULL,
	state       TEXT NOT NULL,
	attempt     INTEGER NOT NULL DEFAULT 0,
	started_at  INTEGER NOT NULL DEFAULT 0,
	finished_at INTEGER NOT NULL DEFAULT 0,
	error       TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (job_id, idx)
);

-- Log lines are redacted before they are written.
CREATE TABLE job_logs (
	job_id  INTEGER NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
	seq     INTEGER NOT NULL,
	ts      INTEGER NOT NULL, -- unix milliseconds
	level   TEXT NOT NULL,
	step    TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL,
	PRIMARY KEY (job_id, seq)
);
