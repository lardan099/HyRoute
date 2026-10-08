-- Panel users and the audit log in the UI (P4-03): the newest login of each
-- user, taken from the audit log for the logins made before, and indexes
-- for the filters of the audit listing (newest first, by id).
ALTER TABLE users ADD COLUMN last_login_at INTEGER NOT NULL DEFAULT 0;
UPDATE users SET last_login_at = COALESCE((
	SELECT MAX(ts) FROM audit_log WHERE audit_log.user_id = users.id AND action IN ('login', 'setup')), 0);

CREATE INDEX audit_log_user ON audit_log (user_id, id);
CREATE INDEX audit_log_action ON audit_log (action, id);
CREATE INDEX audit_log_target ON audit_log (target, id);
