-- Config presets (P2-08): sections of a Hysteria server config without
-- secrets and without server addresses, as YAML. notes say what was left
-- out when the preset was made (JSON list of strings).
CREATE TABLE presets (
	id         INTEGER PRIMARY KEY,
	name       TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
	config     TEXT NOT NULL,
	notes      TEXT NOT NULL DEFAULT '[]',
	created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
