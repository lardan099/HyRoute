-- Preset IDs are never given again (AUTOINCREMENT): a batch, a deployment
-- or a rule template that names a preset by its ID must not find another
-- preset under it after the first one was deleted.
CREATE TABLE presets_new (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK (length(name) BETWEEN 1 AND 64),
	config     TEXT NOT NULL,
	notes      TEXT NOT NULL DEFAULT '[]',
	created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
INSERT INTO presets_new (id, name, config, notes, created_by, created_at, updated_at)
	SELECT id, name, config, notes, created_by, created_at, updated_at FROM presets;
DROP TABLE presets;
ALTER TABLE presets_new RENAME TO presets;
