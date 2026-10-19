-- The trusted SSH host key of each server (trust on first use, confirmed
-- by an admin). A changed key blocks connections until trusted again.
CREATE TABLE host_keys (
	server_id   INTEGER PRIMARY KEY REFERENCES servers (id) ON DELETE CASCADE,
	key_type    TEXT NOT NULL,
	key         BLOB NOT NULL, -- SSH wire format
	fingerprint TEXT NOT NULL, -- SHA256:… as ssh-keygen -l prints it
	trusted_at  INTEGER NOT NULL,
	trusted_by  INTEGER REFERENCES users (id) ON DELETE SET NULL
);
