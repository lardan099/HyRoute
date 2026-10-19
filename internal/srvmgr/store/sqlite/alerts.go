package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const channelCols = `id, name, kind, enabled, settings, events, quiet, secret IS NOT NULL, created_by, created_at, updated_at`

func scanChannel(r rowScanner) (model.AlertChannel, error) {
	var c model.AlertChannel
	var kind, settings, evs, quiet string
	var by sql.NullInt64
	var created, updated int64
	err := r.Scan(&c.ID, &c.Name, &kind, &c.Enabled, &settings, &evs, &quiet, &c.HasSecret, &by, &created, &updated)
	if err != nil {
		return c, err
	}
	c.Kind, c.Settings, c.CreatedBy = model.ChannelKind(kind), json.RawMessage(settings), by.Int64
	c.CreatedAt, c.UpdatedAt = fromUnix(created), fromUnix(updated)
	json.Unmarshal([]byte(evs), &c.Events)
	json.Unmarshal([]byte(quiet), &c.Quiet)
	return c, nil
}

// channelJSON are the JSON columns of a channel.
func channelJSON(c model.AlertChannel) (settings, evs, quiet string) {
	settings = string(c.Settings)
	if settings == "" {
		settings = "{}"
	}
	if c.Events == nil {
		c.Events = []model.EventKind{}
	}
	e, _ := json.Marshal(c.Events)
	q, _ := json.Marshal(c.Quiet)
	return settings, string(e), string(q)
}

// CreateAlertChannel inserts c (setting c.ID) with the secret seal
// returns once the ID is known (seal may be nil or return nil: none).
func (d *DB) CreateAlertChannel(ctx context.Context, c *model.AlertChannel, seal func(id int64) ([]byte, error)) error {
	settings, evs, quiet := channelJSON(*c)
	return d.tx(ctx, func(t *sql.Tx) error {
		res, err := t.ExecContext(ctx, `INSERT INTO alert_channels (name, kind, enabled, settings, events, quiet, created_by, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, c.Name, string(c.Kind), c.Enabled, settings, evs, quiet, nullID(c.CreatedBy), unixTime(c.CreatedAt), unixTime(c.UpdatedAt))
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
			if b != nil {
				if _, err := t.ExecContext(ctx, `UPDATE alert_channels SET secret = ? WHERE id = ?`, b, id); err != nil {
					return err
				}
				c.HasSecret = true
			}
		}
		c.ID = id
		return nil
	})
}

// UpdateAlertChannel replaces the name, enabled, settings, events and
// quiet hours of c (not its kind). seal nil keeps the secret; a seal that
// returns nil removes it.
func (d *DB) UpdateAlertChannel(ctx context.Context, c model.AlertChannel, seal func(id int64) ([]byte, error)) error {
	settings, evs, quiet := channelJSON(c)
	return d.tx(ctx, func(t *sql.Tx) error {
		res, err := t.ExecContext(ctx, `UPDATE alert_channels SET name = ?, enabled = ?, settings = ?, events = ?, quiet = ?, updated_at = ? WHERE id = ?`,
			c.Name, c.Enabled, settings, evs, quiet, unixTime(c.UpdatedAt), c.ID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		if seal == nil {
			return nil
		}
		b, err := seal(c.ID)
		if err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `UPDATE alert_channels SET secret = ? WHERE id = ?`, b, c.ID)
		return err
	})
}

func (d *DB) DeleteAlertChannel(ctx context.Context, id int64) error {
	res, err := d.db.ExecContext(ctx, `DELETE FROM alert_channels WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) AlertChannelByID(ctx context.Context, id int64) (model.AlertChannel, error) {
	c, err := scanChannel(d.db.QueryRowContext(ctx, `SELECT `+channelCols+` FROM alert_channels WHERE id = ?`, id))
	return c, notFound(err)
}

// ListAlertChannels is every channel, oldest first.
func (d *DB) ListAlertChannels(ctx context.Context) ([]model.AlertChannel, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+channelCols+` FROM alert_channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AlertChannel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AlertChannelSecret is the sealed secret of a channel (nil: none).
func (d *DB) AlertChannelSecret(ctx context.Context, id int64) ([]byte, error) {
	var b []byte
	err := d.db.QueryRowContext(ctx, `SELECT secret FROM alert_channels WHERE id = ?`, id).Scan(&b)
	return b, notFound(err)
}
