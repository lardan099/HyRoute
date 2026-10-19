-- Batches (P4-07): one action over many servers as ordinary jobs, a
-- canary first, then a few at a time. The controller's batch runner goes
-- on with a running batch after a restart from these rows. params are the
-- action's choices (JSON, no secrets); stop says why no more jobs start
-- (user, failed, denied).
CREATE TABLE batches (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	action      TEXT NOT NULL CHECK (action IN ('maintain', 'geo', 'preset', 'routing', 'tuning', 'rotate')),
	params      TEXT NOT NULL DEFAULT '{}',
	parallel    INTEGER NOT NULL CHECK (parallel BETWEEN 1 AND 10),
	state       TEXT NOT NULL CHECK (state IN ('running', 'stopping', 'completed', 'failed', 'stopped')),
	stop        TEXT NOT NULL DEFAULT '' CHECK (stop IN ('', 'user', 'failed', 'denied')),
	stopped_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
	retry_of    INTEGER REFERENCES batches (id) ON DELETE SET NULL,
	created_by  INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	finished_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX batches_state ON batches (state);
CREATE INDEX batches_retry_of ON batches (retry_of);

-- The servers of a batch in their order (idx 0 first). A deleted server
-- leaves its batches: one with a job in progress cannot be deleted.
CREATE TABLE batch_items (
	batch_id  INTEGER NOT NULL REFERENCES batches (id) ON DELETE CASCADE,
	idx       INTEGER NOT NULL,
	server_id INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	state     TEXT NOT NULL CHECK (state IN ('pending', 'starting', 'running', 'completed', 'unchanged', 'failed', 'skipped')),
	job_id    INTEGER REFERENCES jobs (id) ON DELETE SET NULL,
	canary    INTEGER NOT NULL DEFAULT 0,
	message   TEXT NOT NULL DEFAULT '',
	at        INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (batch_id, idx)
);
CREATE INDEX batch_items_server ON batch_items (server_id);
