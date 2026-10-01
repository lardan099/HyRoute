-- Health checks of servers with Hysteria installed, kept 7 days. status
-- is healthy, degraded or offline; reason explains a status that is not
-- healthy; listening is NULL when it could not be checked.
CREATE TABLE health_checks (
	server_id  INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	at         INTEGER NOT NULL,
	status     TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'offline')),
	reason     TEXT NOT NULL DEFAULT '',
	ssh_ms     INTEGER NOT NULL DEFAULT 0,
	service    TEXT NOT NULL DEFAULT '',
	listening  INTEGER CHECK (listening IN (0, 1)),
	udp        TEXT NOT NULL CHECK (udp IN ('ok', 'no_answer', 'error', 'skipped')),
	udp_ms     INTEGER NOT NULL DEFAULT 0,
	egress     TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (server_id, at)
) WITHOUT ROWID;
