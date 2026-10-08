package sqlite

import (
	"context"
	"encoding/json"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (d *DB) SetDrift(ctx context.Context, dr model.Drift) error {
	var js [4][]byte
	for i, v := range []any{nonNil(dr.Checked), nonNil(dr.Skipped), nonNil(dr.Items), nonNil(dr.Reverts)} {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		js[i] = b
	}
	_, err := d.db.ExecContext(ctx, `INSERT OR REPLACE INTO drift (server_id, at, error, checked, skipped, items, config, attention_at, reverts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dr.ServerID, unixTime(dr.At), dr.Error, string(js[0]), string(js[1]), string(js[2]), dr.Config, unixTime(dr.AttentionAt), string(js[3]))
	return err
}

// nonNil keeps an empty list a list in JSON ([], not null).
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

const driftCols = `server_id, at, error, checked, skipped, items, config, attention_at, reverts`

func scanDrift(r rowScanner) (model.Drift, error) {
	var dr model.Drift
	var at, attention int64
	var checked, skipped, items, reverts string
	if err := r.Scan(&dr.ServerID, &at, &dr.Error, &checked, &skipped, &items, &dr.Config, &attention, &reverts); err != nil {
		return dr, err
	}
	dr.At, dr.AttentionAt = fromUnix(at), fromUnix(attention)
	for _, p := range []struct {
		raw string
		v   any
	}{{checked, &dr.Checked}, {skipped, &dr.Skipped}, {items, &dr.Items}, {reverts, &dr.Reverts}} {
		if err := json.Unmarshal([]byte(p.raw), p.v); err != nil {
			return dr, err
		}
	}
	return dr, nil
}

func (d *DB) Drift(ctx context.Context, serverID int64) (model.Drift, error) {
	dr, err := scanDrift(d.db.QueryRowContext(ctx, `SELECT `+driftCols+` FROM drift WHERE server_id = ?`, serverID))
	return dr, notFound(err)
}

func (d *DB) Drifts(ctx context.Context) ([]model.Drift, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+driftCols+` FROM drift ORDER BY server_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Drift
	for rows.Next() {
		dr, err := scanDrift(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dr)
	}
	return out, rows.Err()
}
