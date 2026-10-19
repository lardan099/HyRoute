package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

const eventCols = `id, kind, dedupe_key, severity, subject, subject_id, text, count, opened_at, last_at, closed_at, close_text`

func scanEvent(r rowScanner) (model.Event, error) {
	var e model.Event
	var kind, sev string
	var opened, last int64
	var closed sql.NullInt64
	err := r.Scan(&e.ID, &kind, &e.Key, &sev, &e.Subject, &e.SubjectID, &e.Text, &e.Count, &opened, &last, &closed, &e.CloseText)
	e.Kind, e.Severity = model.EventKind(kind), model.Severity(sev)
	e.OpenedAt, e.LastAt = fromUnix(opened), fromUnix(last)
	if closed.Valid {
		e.ClosedAt = fromUnix(closed.Int64)
	}
	return e, err
}

// RaiseEvent opens e at e.OpenedAt, or, while an event of its key is
// open, glues it into that one: the count grows, and the text, severity,
// subject and last time become e's. opened: a new event.
func (d *DB) RaiseEvent(ctx context.Context, e model.Event) (out model.Event, opened bool, err error) {
	at := e.OpenedAt
	err = d.tx(ctx, func(t *sql.Tx) error {
		var id int64
		err := t.QueryRowContext(ctx, `SELECT id FROM events WHERE dedupe_key = ? AND closed_at IS NULL`, e.Key).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			res, err := t.ExecContext(ctx, `INSERT INTO events (kind, dedupe_key, severity, subject, subject_id, text, count, opened_at, last_at)
				VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`, string(e.Kind), e.Key, string(e.Severity), e.Subject, e.SubjectID, e.Text, unixTime(at), unixTime(at))
			if err != nil {
				return err
			}
			if id, err = res.LastInsertId(); err != nil {
				return err
			}
			opened = true
		case err != nil:
			return err
		default:
			if _, err := t.ExecContext(ctx, `UPDATE events SET count = count + 1, last_at = ?, text = ?, severity = ?, subject = ?, subject_id = ? WHERE id = ?`,
				unixTime(at), e.Text, string(e.Severity), e.Subject, e.SubjectID, id); err != nil {
				return err
			}
		}
		out, err = scanEvent(t.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE id = ?`, id))
		return err
	})
	return out, opened, err
}

// CloseEvent closes the open event of key at at with text; closed: there
// was one.
func (d *DB) CloseEvent(ctx context.Context, key string, at time.Time, text string) (out model.Event, closed bool, err error) {
	err = d.tx(ctx, func(t *sql.Tx) error {
		var id int64
		err := t.QueryRowContext(ctx, `SELECT id FROM events WHERE dedupe_key = ? AND closed_at IS NULL`, key).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		} else if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `UPDATE events SET closed_at = ?, close_text = ? WHERE id = ?`, unixTime(at), text, id); err != nil {
			return err
		}
		closed = true
		out, err = scanEvent(t.QueryRowContext(ctx, `SELECT `+eventCols+` FROM events WHERE id = ?`, id))
		return err
	})
	return out, closed, err
}

// ListEvents are events newest first.
func (d *DB) ListEvents(ctx context.Context, f model.EventFilter) ([]model.Event, error) {
	q := `SELECT ` + eventCols + ` FROM events WHERE 1 = 1`
	var args []any
	if f.OpenOnly {
		q += ` AND closed_at IS NULL`
	}
	if f.BeforeID > 0 {
		q += ` AND id < ?`
		args = append(args, f.BeforeID)
	}
	q += ` ORDER BY id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
		args = append(args, f.Limit)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PruneEvents drops events closed before before; open ones stay.
func (d *DB) PruneEvents(ctx context.Context, before time.Time) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM events WHERE closed_at IS NOT NULL AND closed_at < ?`, unixTime(before))
	return err
}
