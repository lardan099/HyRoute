-- Where Hysteria is on a server and whether HyRoute installed it. Deploy
-- records the standard paths with managed = 1; import records what it
-- found with managed = 0. Service status, control and config editing work
-- on these paths.
CREATE TABLE installations (
	server_id    INTEGER PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
	binary_path  TEXT NOT NULL,
	config_path  TEXT NOT NULL,
	unit         TEXT NOT NULL,
	service_user TEXT NOT NULL DEFAULT '',
	version      TEXT NOT NULL DEFAULT '',
	managed      INTEGER NOT NULL DEFAULT 0 CHECK (managed IN (0, 1)),
	updated_at   INTEGER NOT NULL
);
