-- Cascades (P3-01): a chain of servers, entry first and exit last, and a
-- link between each pair of neighbours (link idx joins node idx and
-- idx + 1). Phase 3 deploys two nodes; the schema has N.
CREATE TABLE chains (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
	notes      TEXT NOT NULL DEFAULT '',
	created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);

-- A server of a chain cannot be deleted (no ON DELETE): its link is
-- removed with a job first.
CREATE TABLE chain_nodes (
	chain_id  INTEGER NOT NULL REFERENCES chains (id) ON DELETE CASCADE,
	idx       INTEGER NOT NULL CHECK (idx >= 0),
	server_id INTEGER NOT NULL REFERENCES servers (id),
	PRIMARY KEY (chain_id, idx),
	UNIQUE (chain_id, server_id)
);
CREATE INDEX chain_nodes_server ON chain_nodes (server_id);

-- params: JSON without secrets; secrets: sealed (secrets.Keyring, context
-- chain/<id>/link/<idx>). from_revision and to_revision are the config
-- revisions of both servers the link was last deployed with, config_sha256
-- the hash of its client config.
CREATE TABLE chain_links (
	chain_id      INTEGER NOT NULL REFERENCES chains (id) ON DELETE CASCADE,
	idx           INTEGER NOT NULL CHECK (idx >= 0),
	params        TEXT NOT NULL DEFAULT '{}',
	secrets       BLOB,
	state         TEXT NOT NULL CHECK (state IN ('new', 'linking', 'active', 'stale', 'unlinking', 'failed')),
	from_revision INTEGER NOT NULL DEFAULT 0,
	to_revision   INTEGER NOT NULL DEFAULT 0,
	config_sha256 TEXT NOT NULL DEFAULT '',
	updated_at    INTEGER NOT NULL,
	PRIMARY KEY (chain_id, idx)
);

-- Roles follow the place of a server in the chains from now on. Roles set
-- by hand before had no chain behind them.
UPDATE servers SET role = 'standalone' WHERE role <> 'standalone';
