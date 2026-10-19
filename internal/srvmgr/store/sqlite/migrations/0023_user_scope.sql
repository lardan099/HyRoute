-- foreign_keys: off
-- Permissions and scope (P4-04): the role «менеджер клиентов» (clients) and
-- the scope of each user, JSON: {"all":true} or {"tags":[...]}. Existing
-- users reach all servers, as before. SQLite cannot change a CHECK
-- constraint, so users is rebuilt; other tables reference it, so this runs
-- with foreign keys off (a DROP would run their ON DELETE actions) and the
-- runner checks them before it commits. The AUTOINCREMENT sequence is kept:
-- the audit log names users by ID, and a deleted user's ID must not come
-- back.
CREATE TABLE users_new (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
	password_hash TEXT NOT NULL,
	role          TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'operator', 'clients', 'readonly')),
	scope         TEXT NOT NULL DEFAULT '{"all":true}',
	disabled      INTEGER NOT NULL DEFAULT 0,
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL,
	last_login_at INTEGER NOT NULL DEFAULT 0
);
INSERT INTO users_new (id, username, password_hash, role, scope, disabled, created_at, updated_at, last_login_at)
	SELECT id, username, password_hash, role, '{"all":true}', disabled, created_at, updated_at, last_login_at FROM users;
DELETE FROM sqlite_sequence WHERE name = 'users_new';
INSERT INTO sqlite_sequence (name, seq) SELECT 'users_new', seq FROM sqlite_sequence WHERE name = 'users';
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
