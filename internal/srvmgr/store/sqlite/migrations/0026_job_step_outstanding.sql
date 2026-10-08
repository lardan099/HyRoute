-- A step that ran and was not undone since: the rollback of a later
-- attempt undoes it too, also when that attempt did not get to it again.
-- Steps recorded before keep the old rule (done or skipped before the
-- failed step).
ALTER TABLE job_steps ADD COLUMN outstanding INTEGER NOT NULL DEFAULT 0;
