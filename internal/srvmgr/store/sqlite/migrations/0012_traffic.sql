-- Traffic per Hysteria user and hour (P2-04), from the stats API: hour is
-- the start of the hour in Unix seconds, tx and rx are bytes (the client's
-- upload and download). Kept 90 days. Which sites were visited is never
-- stored.
CREATE TABLE traffic (
	server_id INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	hour      INTEGER NOT NULL,
	user      TEXT NOT NULL,
	tx        INTEGER NOT NULL DEFAULT 0 CHECK (tx >= 0),
	rx        INTEGER NOT NULL DEFAULT 0 CHECK (rx >= 0),
	PRIMARY KEY (server_id, hour, user)
) WITHOUT ROWID;
