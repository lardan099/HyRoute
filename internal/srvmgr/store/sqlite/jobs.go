package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const jobCols = `id, kind, server_id, state, current_step, params, data, attempt, error_message, error_details, created_by, created_at, started_at, finished_at, lease_owner, lease_until`

func scanJob(r rowScanner) (model.Job, error) {
	var j model.Job
	var server, by sql.NullInt64
	var state, params, data string
	var created, started, finished, lease int64
	err := r.Scan(&j.ID, &j.Kind, &server, &state, &j.CurrentStep, &params, &data, &j.Attempt, &j.ErrorMessage, &j.ErrorDetails, &by, &created, &started, &finished, &j.LeaseOwner, &lease)
	if err != nil {
		return j, err
	}
	j.ServerID, j.CreatedBy, j.State = server.Int64, by.Int64, model.JobState(state)
	j.Params = json.RawMessage(params)
	if err := json.Unmarshal([]byte(data), &j.Data); err != nil {
		return j, err
	}
	j.CreatedAt, j.StartedAt, j.FinishedAt, j.LeaseUntil = fromUnix(created), fromUnix(started), fromUnix(finished), fromUnix(lease)
	return j, nil
}

func dataJSON(m map[string]string) string {
	if m == nil {
		return "{}"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func nullID(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: id != 0} }

// unfinished lists the states of jobs that are not done.
const unfinished = `state NOT IN ('completed', 'failed')`

func (d *DB) CreateJob(ctx context.Context, j *model.Job, steps []model.JobStep, seal func(int64) ([]byte, error)) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		if j.ServerID != 0 {
			var n int
			if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE server_id = ? AND `+unfinished, j.ServerID).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return store.ErrConflict
			}
		}
		params := string(j.Params)
		if params == "" {
			params = "{}"
		}
		res, err := t.ExecContext(ctx, `INSERT INTO jobs (kind, server_id, state, current_step, params, data, attempt, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			j.Kind, nullID(j.ServerID), string(j.State), j.CurrentStep, params, dataJSON(j.Data), max(j.Attempt, 1), nullID(j.CreatedBy), unixTime(j.CreatedAt))
		if err != nil {
			return err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		if seal != nil {
			b, err := seal(id)
			if err != nil {
				return err
			}
			if _, err := t.ExecContext(ctx, `UPDATE jobs SET secret = ? WHERE id = ?`, b, id); err != nil {
				return err
			}
		}
		for i, s := range steps {
			if _, err := t.ExecContext(ctx, `INSERT INTO job_steps (job_id, idx, name, phase, state) VALUES (?, ?, ?, ?, ?)`, id, i, s.Name, string(s.Phase), string(model.StepPending)); err != nil {
				return err
			}
		}
		j.ID, j.Attempt = id, max(j.Attempt, 1)
		return nil
	})
}

func (d *DB) JobByID(ctx context.Context, id int64) (model.Job, error) {
	j, err := scanJob(d.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = ?`, id))
	return j, notFound(err)
}

func (d *DB) JobSecret(ctx context.Context, id int64) ([]byte, error) {
	var b []byte
	err := d.db.QueryRowContext(ctx, `SELECT secret FROM jobs WHERE id = ?`, id).Scan(&b)
	return b, notFound(err)
}

func (d *DB) queryJobs(ctx context.Context, q string, args ...any) ([]model.Job, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var js []model.Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		js = append(js, j)
	}
	return js, rows.Err()
}

func (d *DB) ListJobs(ctx context.Context, f model.JobFilter) ([]model.Job, error) {
	var where []string
	var args []any
	if f.ServerID != 0 {
		where, args = append(where, "server_id = ?"), append(args, f.ServerID)
	}
	if f.BeforeID != 0 {
		where, args = append(where, "id < ?"), append(args, f.BeforeID)
	}
	q := `SELECT ` + jobCols + ` FROM jobs`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return d.queryJobs(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
}

func (d *DB) UnfinishedJobs(ctx context.Context) ([]model.Job, error) {
	return d.queryJobs(ctx, `SELECT `+jobCols+` FROM jobs WHERE `+unfinished+` ORDER BY id`)
}

func (d *DB) ClaimJob(ctx context.Context, id int64, owner string, until time.Time) (bool, error) {
	res, err := d.db.ExecContext(ctx, `UPDATE jobs SET lease_owner = ?, lease_until = ? WHERE id = ? AND state = 'queued' AND (lease_owner = '' OR lease_owner = ?)`,
		owner, unixTime(until), id, owner)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

func (d *DB) ExtendLease(ctx context.Context, id int64, owner string, until time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE jobs SET lease_until = ? WHERE id = ? AND lease_owner = ?`, unixTime(until), id, owner)
	return err
}

func (d *DB) UpdateJob(ctx context.Context, j model.Job) error {
	res, err := d.db.ExecContext(ctx, `UPDATE jobs SET state = ?, current_step = ?, data = ?, attempt = ?, error_message = ?, error_details = ?, started_at = ?, finished_at = ?, lease_owner = ?, lease_until = ? WHERE id = ?`,
		string(j.State), j.CurrentStep, dataJSON(j.Data), j.Attempt, j.ErrorMessage, j.ErrorDetails, unixTime(j.StartedAt), unixTime(j.FinishedAt), j.LeaseOwner, unixTime(j.LeaseUntil), j.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) JobSteps(ctx context.Context, jobID int64) ([]model.JobStep, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT job_id, idx, name, phase, state, attempt, started_at, finished_at, error FROM job_steps WHERE job_id = ? ORDER BY idx`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ss []model.JobStep
	for rows.Next() {
		var s model.JobStep
		var phase, state string
		var started, finished int64
		if err := rows.Scan(&s.JobID, &s.Idx, &s.Name, &phase, &state, &s.Attempt, &started, &finished, &s.Error); err != nil {
			return nil, err
		}
		s.Phase, s.State = model.JobState(phase), model.StepState(state)
		s.StartedAt, s.FinishedAt = fromUnix(started), fromUnix(finished)
		ss = append(ss, s)
	}
	return ss, rows.Err()
}

func (d *DB) UpdateJobStep(ctx context.Context, s model.JobStep) error {
	_, err := d.db.ExecContext(ctx, `UPDATE job_steps SET state = ?, attempt = ?, started_at = ?, finished_at = ?, error = ? WHERE job_id = ? AND idx = ?`,
		string(s.State), s.Attempt, unixTime(s.StartedAt), unixTime(s.FinishedAt), s.Error, s.JobID, s.Idx)
	return err
}

func (d *DB) AppendJobLog(ctx context.Context, l *model.JobLog) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		var seq int64
		if err := t.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) + 1 FROM job_logs WHERE job_id = ?`, l.JobID).Scan(&seq); err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `INSERT INTO job_logs (job_id, seq, ts, level, step, message) VALUES (?, ?, ?, ?, ?, ?)`,
			l.JobID, seq, l.Time.UnixMilli(), l.Level, l.Step, l.Message); err != nil {
			return err
		}
		l.Seq = seq
		return nil
	})
}

func (d *DB) JobLogs(ctx context.Context, jobID, after int64, limit int) ([]model.JobLog, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	rows, err := d.db.QueryContext(ctx, `SELECT job_id, seq, ts, level, step, message FROM job_logs WHERE job_id = ? AND seq > ? ORDER BY seq LIMIT ?`, jobID, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ls []model.JobLog
	for rows.Next() {
		var l model.JobLog
		var ts int64
		if err := rows.Scan(&l.JobID, &l.Seq, &ts, &l.Level, &l.Step, &l.Message); err != nil {
			return nil, err
		}
		l.Time = time.UnixMilli(ts)
		ls = append(ls, l)
	}
	return ls, rows.Err()
}
