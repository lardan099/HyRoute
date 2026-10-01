package sqlite

import (
	"context"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (d *DB) AddTraffic(ctx context.Context, serverID int64, at time.Time, users map[string]model.TrafficHour) error {
	if len(users) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	hour := at.UTC().Truncate(time.Hour).Unix()
	for user, t := range users {
		if t.Tx == 0 && t.Rx == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO traffic (server_id, hour, user, tx, rx) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (server_id, hour, user) DO UPDATE SET tx = tx + excluded.tx, rx = rx + excluded.rx`,
			serverID, hour, user, max(t.Tx, 0), max(t.Rx, 0)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (d *DB) Traffic(ctx context.Context, serverID int64, from, to time.Time) ([]model.TrafficHour, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT hour, user, tx, rx FROM traffic
		WHERE server_id = ? AND hour >= ? AND hour < ? ORDER BY hour, user`,
		serverID, from.UTC().Truncate(time.Hour).Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TrafficHour{}
	for rows.Next() {
		t := model.TrafficHour{ServerID: serverID}
		var hour int64
		if err := rows.Scan(&hour, &t.User, &t.Tx, &t.Rx); err != nil {
			return nil, err
		}
		t.Hour = time.Unix(hour, 0).UTC()
		out = append(out, t)
	}
	return out, rows.Err()
}

func (d *DB) PruneTraffic(ctx context.Context, before time.Time) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM traffic WHERE hour < ?`, before.Unix())
	return err
}
