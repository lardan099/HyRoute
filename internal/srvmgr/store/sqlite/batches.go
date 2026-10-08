package sqlite

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// batchCols are the columns of a batch; retried_by is the newest batch
// that retries it.
const batchCols = `b.id, b.action, b.params, b.parallel, b.state, b.stop, COALESCE(b.stopped_by, 0), COALESCE(b.retry_of, 0),
	COALESCE((SELECT MAX(r.id) FROM batches r WHERE r.retry_of = b.id), 0), COALESCE(b.created_by, 0), b.created_at, b.updated_at, b.finished_at`

func scanBatch(r rowScanner) (model.Batch, error) {
	var b model.Batch
	var action, params, state, stop string
	var created, updated, finished int64
	err := r.Scan(&b.ID, &action, &params, &b.Parallel, &state, &stop, &b.StoppedBy, &b.RetryOf, &b.RetriedBy, &b.CreatedBy, &created, &updated, &finished)
	b.Action, b.Params, b.State, b.Stop = model.BatchAction(action), []byte(params), model.BatchState(state), model.BatchStop(stop)
	b.CreatedAt, b.UpdatedAt, b.FinishedAt = fromUnix(created), fromUnix(updated), fromUnix(finished)
	return b, err
}

// CreateBatch inserts b with its items, setting b.ID.
func (d *DB) CreateBatch(ctx context.Context, b *model.Batch) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		params := string(b.Params)
		if params == "" {
			params = "{}"
		}
		res, err := t.ExecContext(ctx, `INSERT INTO batches (action, params, parallel, state, stop, stopped_by, retry_of, created_by, created_at, updated_at, finished_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			string(b.Action), params, b.Parallel, string(b.State), string(b.Stop), nullID(b.StoppedBy), nullID(b.RetryOf), nullID(b.CreatedBy),
			unixTime(b.CreatedAt), unixTime(b.UpdatedAt), unixTime(b.FinishedAt))
		if err != nil {
			return err
		}
		if b.ID, err = res.LastInsertId(); err != nil {
			return err
		}
		return writeItems(ctx, t, *b)
	})
}

// writeItems replaces the items of b.
func writeItems(ctx context.Context, t *sql.Tx, b model.Batch) error {
	if _, err := t.ExecContext(ctx, `DELETE FROM batch_items WHERE batch_id = ?`, b.ID); err != nil {
		return err
	}
	for _, it := range b.Items {
		if _, err := t.ExecContext(ctx, `INSERT INTO batch_items (batch_id, idx, server_id, state, job_id, canary, message, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			b.ID, it.Idx, it.ServerID, string(it.State), nullID(it.JobID), it.Canary, it.Message, unixTime(it.At)); err != nil {
			return err
		}
	}
	return nil
}

// SaveBatch writes the state, stop, times and every item of b.
func (d *DB) SaveBatch(ctx context.Context, b model.Batch) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		res, err := t.ExecContext(ctx, `UPDATE batches SET state = ?, stop = ?, stopped_by = ?, updated_at = ?, finished_at = ? WHERE id = ?`,
			string(b.State), string(b.Stop), nullID(b.StoppedBy), unixTime(b.UpdatedAt), unixTime(b.FinishedAt), b.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return writeItems(ctx, t, b)
	})
}

// BatchByID is a batch with its items.
func (d *DB) BatchByID(ctx context.Context, id int64) (model.Batch, error) {
	bs, err := d.queryBatches(ctx, `SELECT `+batchCols+` FROM batches b WHERE b.id = ?`, id)
	if err != nil {
		return model.Batch{}, err
	}
	if len(bs) == 0 {
		return model.Batch{}, store.ErrNotFound
	}
	return bs[0], nil
}

// ListBatches are batches newest first.
func (d *DB) ListBatches(ctx context.Context, f model.BatchFilter) ([]model.Batch, error) {
	var where []string
	var args []any
	if f.BeforeID != 0 {
		where, args = append(where, "b.id < ?"), append(args, f.BeforeID)
	}
	if f.Within != nil {
		// Every server of the batch, and the node its action downloads
		// through, are in the set; a batch of no server is not.
		where = append(where, `EXISTS (SELECT 1 FROM batch_items i WHERE i.batch_id = b.id)
			AND NOT EXISTS (SELECT 1 FROM batch_items i WHERE i.batch_id = b.id AND i.server_id NOT IN (SELECT value FROM json_each(?)))
			AND COALESCE(json_extract(b.params, '$.via'), 0) IN (SELECT 0 UNION ALL SELECT value FROM json_each(?))`)
		w := withinArgs(*f.Within)
		args = append(args, w[0], w[1])
	}
	q := `SELECT ` + batchCols + ` FROM batches b`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return d.queryBatches(ctx, q+` ORDER BY b.id DESC LIMIT ?`, append(args, limit)...)
}

// UnfinishedBatches are the running and stopping batches, oldest first.
func (d *DB) UnfinishedBatches(ctx context.Context) ([]model.Batch, error) {
	return d.queryBatches(ctx, `SELECT `+batchCols+` FROM batches b WHERE b.state IN ('running', 'stopping') ORDER BY b.id`)
}

// queryBatches reads batches and their items.
func (d *DB) queryBatches(ctx context.Context, q string, args ...any) ([]model.Batch, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	out := []model.Batch{}
	for rows.Next() {
		b, err := scanBatch(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, b)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return out, nil
	}
	at := make(map[int64]int, len(out))
	ids := make([]string, len(out))
	for i, b := range out {
		at[b.ID] = i
		ids[i] = strconv.FormatInt(b.ID, 10)
	}
	rows, err = d.db.QueryContext(ctx, `SELECT batch_id, idx, server_id, state, COALESCE(job_id, 0), canary, message, at FROM batch_items
		WHERE batch_id IN (`+strings.Join(ids, ",")+`) ORDER BY batch_id, idx`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var batch, when int64
		var it model.BatchItem
		var state string
		if err := rows.Scan(&batch, &it.Idx, &it.ServerID, &state, &it.JobID, &it.Canary, &it.Message, &when); err != nil {
			return nil, err
		}
		it.State, it.At = model.BatchItemState(state), fromUnix(when)
		if i, ok := at[batch]; ok {
			out[i].Items = append(out[i].Items, it)
		}
	}
	return out, rows.Err()
}
