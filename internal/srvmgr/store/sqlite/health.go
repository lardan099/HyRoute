package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (d *DB) AddHealth(ctx context.Context, h model.Health) error {
	var listening sql.NullBool
	if h.Listening != nil {
		listening = sql.NullBool{Bool: *h.Listening, Valid: true}
	}
	_, err := d.db.ExecContext(ctx, `INSERT OR REPLACE INTO health_checks (server_id, at, status, reason, ssh_ms, service, listening, udp, udp_ms, egress)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		h.ServerID, h.At.Unix(), string(h.Status), h.Reason, h.SSHMillis, h.Service, listening, h.UDP, h.UDPMillis, h.Egress)
	return err
}

func (d *DB) HealthHistory(ctx context.Context, serverID int64, since time.Time, limit int) ([]model.Health, error) {
	if limit <= 0 {
		limit = -1 // SQLite: no limit
	}
	rows, err := d.db.QueryContext(ctx, `SELECT at, status, reason, ssh_ms, service, listening, udp, udp_ms, egress FROM health_checks
		WHERE server_id = ? AND at >= ? ORDER BY at DESC LIMIT ?`, serverID, since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Health{}
	for rows.Next() {
		h := model.Health{ServerID: serverID}
		var at int64
		var status string
		var listening sql.NullBool
		if err := rows.Scan(&at, &status, &h.Reason, &h.SSHMillis, &h.Service, &listening, &h.UDP, &h.UDPMillis, &h.Egress); err != nil {
			return nil, err
		}
		h.At, h.Status = time.Unix(at, 0).UTC(), model.ServerState(status)
		if listening.Valid {
			v := listening.Bool
			h.Listening = &v
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (d *DB) PruneHealth(ctx context.Context, before time.Time) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM health_checks WHERE at < ?`, before.Unix())
	return err
}
