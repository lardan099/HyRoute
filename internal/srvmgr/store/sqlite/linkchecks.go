package sqlite

import (
	"context"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (d *DB) AddLinkCheck(ctx context.Context, c model.LinkCheck) error {
	_, err := d.db.ExecContext(ctx, `INSERT OR REPLACE INTO link_checks (chain_id, idx, at, status, reason, service, handshake_ms, tcp_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ChainID, c.Idx, unixTime(c.At), string(c.Status), c.Reason, c.Service, c.HandshakeMillis, c.TCPMillis)
	return err
}

func (d *DB) LinkChecks(ctx context.Context, chainID int64, idx int, since time.Time, limit int) ([]model.LinkCheck, error) {
	q := `SELECT chain_id, idx, at, status, reason, service, handshake_ms, tcp_ms FROM link_checks WHERE chain_id = ? AND idx = ? AND at >= ? ORDER BY at DESC`
	args := []any{chainID, idx, unixTime(since)}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.LinkCheck
	for rows.Next() {
		var c model.LinkCheck
		var at int64
		var status string
		if err := rows.Scan(&c.ChainID, &c.Idx, &at, &status, &c.Reason, &c.Service, &c.HandshakeMillis, &c.TCPMillis); err != nil {
			return nil, err
		}
		c.At, c.Status = fromUnix(at), model.ServerState(status)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) PruneLinkChecks(ctx context.Context, before time.Time) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM link_checks WHERE at < ?`, unixTime(before))
	return err
}
