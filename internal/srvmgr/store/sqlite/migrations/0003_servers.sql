CREATE TABLE servers (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
	tags       TEXT NOT NULL DEFAULT '[]', -- JSON array of strings
	country    TEXT NOT NULL DEFAULT '',
	location   TEXT NOT NULL DEFAULT '',
	host       TEXT NOT NULL,
	ssh_port   INTEGER NOT NULL CHECK (ssh_port BETWEEN 1 AND 65535),
	ssh_user   TEXT NOT NULL,
	auth_type  TEXT NOT NULL CHECK (auth_type IN ('password', 'key')),
	role       TEXT NOT NULL CHECK (role IN ('standalone', 'entry', 'relay', 'exit')),
	notes      TEXT NOT NULL DEFAULT '',
	state      TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

-- SSH credentials, sealed (secrets.Keyring, context server/<id>/<kind>).
CREATE TABLE server_credentials (
	server_id  INTEGER NOT NULL REFERENCES servers (id) ON DELETE CASCADE,
	kind       TEXT NOT NULL CHECK (kind IN ('ssh_password', 'ssh_key', 'ssh_key_passphrase')),
	sealed     BLOB NOT NULL,
	updated_at INTEGER NOT NULL,
	PRIMARY KEY (server_id, kind)
);
