package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

func (d *DB) SetServerGeo(ctx context.Context, g model.ServerGeo) error {
	_, err := d.db.ExecContext(ctx, `INSERT OR REPLACE INTO server_geo (server_id, release, geoip, geosite, job_id, at) VALUES (?, ?, ?, ?, ?, ?)`,
		g.ServerID, g.Release, g.GeoIP, g.GeoSite, sql.NullInt64{Int64: g.JobID, Valid: g.JobID != 0}, unixTime(g.At))
	return err
}

const geoCols = `server_id, release, geoip, geosite, job_id, at`

func scanGeo(sc interface{ Scan(...any) error }) (model.ServerGeo, error) {
	var g model.ServerGeo
	var job sql.NullInt64
	var at int64
	err := sc.Scan(&g.ServerID, &g.Release, &g.GeoIP, &g.GeoSite, &job, &at)
	g.JobID, g.At = job.Int64, fromUnix(at)
	return g, err
}

func (d *DB) ServerGeo(ctx context.Context, serverID int64) (model.ServerGeo, error) {
	g, err := scanGeo(d.db.QueryRowContext(ctx, `SELECT `+geoCols+` FROM server_geo WHERE server_id = ?`, serverID))
	if errors.Is(err, sql.ErrNoRows) {
		return g, store.ErrNotFound
	}
	return g, err
}

func (d *DB) ServerGeos(ctx context.Context) ([]model.ServerGeo, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+geoCols+` FROM server_geo ORDER BY server_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ServerGeo
	for rows.Next() {
		g, err := scanGeo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}
