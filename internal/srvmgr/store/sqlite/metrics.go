package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func nullFloat(p *float64) sql.NullFloat64 {
	if p == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *p, Valid: true}
}

func floatPtr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func (d *DB) AddMetric(ctx context.Context, m model.Metric) error {
	_, err := d.db.ExecContext(ctx, `INSERT OR REPLACE INTO metrics (server_id, step, at, cpu, mem_used, mem_total, disk_used, disk_total, load1, rx, tx)
		VALUES (?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ServerID, m.At.Unix(), nullFloat(m.CPU), m.MemUsedMiB, m.MemTotalMiB, m.DiskUsedMiB, m.DiskTotalMiB, m.Load1, nullFloat(m.RxBps), nullFloat(m.TxBps))
	return err
}

func (d *DB) Metrics(ctx context.Context, serverID int64, step int, from, to time.Time) ([]model.Metric, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT at, cpu, mem_used, mem_total, disk_used, disk_total, load1, rx, tx FROM metrics
		WHERE server_id = ? AND step = ? AND at >= ? AND at < ? ORDER BY at`, serverID, step, from.Unix(), to.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Metric{}
	for rows.Next() {
		m := model.Metric{ServerID: serverID, Step: step}
		var at int64
		var cpu, rx, tx sql.NullFloat64
		if err := rows.Scan(&at, &cpu, &m.MemUsedMiB, &m.MemTotalMiB, &m.DiskUsedMiB, &m.DiskTotalMiB, &m.Load1, &rx, &tx); err != nil {
			return nil, err
		}
		m.At, m.CPU, m.RxBps, m.TxBps = time.Unix(at, 0).UTC(), floatPtr(cpu), floatPtr(rx), floatPtr(tx)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *DB) CompactMetrics(ctx context.Context, now time.Time, keepSamples, keepAverages time.Duration) error {
	// Periods that ended before now and whose samples are all still kept
	// (an average of what is left of a period would be wrong; that period
	// was averaged earlier, while it was whole).
	const step = model.MetricStep
	end := now.Unix() / step * step
	start := (now.Add(-keepSamples).Unix() + step - 1) / step * step
	return d.tx(ctx, func(t *sql.Tx) error {
		_, err := t.ExecContext(ctx, `INSERT OR REPLACE INTO metrics (server_id, step, at, cpu, mem_used, mem_total, disk_used, disk_total, load1, rx, tx)
			SELECT server_id, ?, at / ? * ?, AVG(cpu), AVG(mem_used), MAX(mem_total), AVG(disk_used), MAX(disk_total), AVG(load1), AVG(rx), AVG(tx)
			FROM metrics WHERE step = 0 AND at < ? AND at >= ?
			GROUP BY server_id, at / ?`,
			step, step, step, end, start, step)
		if err != nil {
			return err
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM metrics WHERE step = 0 AND at < ?`, now.Add(-keepSamples).Unix()); err != nil {
			return err
		}
		_, err = t.ExecContext(ctx, `DELETE FROM metrics WHERE step = ? AND at < ?`, step, now.Add(-keepAverages).Unix())
		return err
	})
}
