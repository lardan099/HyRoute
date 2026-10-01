-- Checks of cascade links from their entries (P3-03), kept 7 days.
CREATE TABLE link_checks (
	chain_id     INTEGER NOT NULL REFERENCES chains (id) ON DELETE CASCADE,
	idx          INTEGER NOT NULL,
	at           INTEGER NOT NULL,
	status       TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'offline')),
	reason       TEXT NOT NULL DEFAULT '',
	service      TEXT NOT NULL DEFAULT '',
	handshake_ms INTEGER NOT NULL DEFAULT 0,
	tcp_ms       INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (chain_id, idx, at)
);
