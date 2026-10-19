-- Events (P4-05): open while they last, closed when they end. One open
-- event per dedupe key: repeats are glued into it (count, last_at).
-- Closed events are kept 30 days.
CREATE TABLE events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	kind       TEXT NOT NULL,
	dedupe_key TEXT NOT NULL,
	severity   TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
	subject    TEXT NOT NULL DEFAULT '',
	subject_id INTEGER NOT NULL DEFAULT 0,
	text       TEXT NOT NULL,
	count      INTEGER NOT NULL DEFAULT 1,
	opened_at  INTEGER NOT NULL,
	last_at    INTEGER NOT NULL,
	closed_at  INTEGER,
	close_text TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX events_open_key ON events (dedupe_key) WHERE closed_at IS NULL;
CREATE INDEX events_closed_at ON events (closed_at);

-- Notification channels (P4-05): Telegram, webhook, SMTP. settings,
-- events (the kinds sent; [] every kind) and quiet (quiet hours) are
-- JSON without secrets; the bot token, webhook signing key or SMTP
-- password is sealed in secret (context alert/<id>/secret).
CREATE TABLE alert_channels (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL,
	kind       TEXT NOT NULL CHECK (kind IN ('telegram', 'webhook', 'smtp')),
	enabled    INTEGER NOT NULL DEFAULT 1,
	settings   TEXT NOT NULL DEFAULT '{}',
	events     TEXT NOT NULL DEFAULT '[]',
	quiet      TEXT NOT NULL DEFAULT '{}',
	secret     BLOB,
	created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
