package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const configCols = `id, server_id, revision, config, sha256, meta, source, from_revision, job_id, created_by, created_at`

func scanConfig(r rowScanner) (model.ServerConfig, error) {
	var c model.ServerConfig
	var meta, source string
	var from, job, by sql.NullInt64
	var at int64
	if err := r.Scan(&c.ID, &c.ServerID, &c.Revision, &c.Sealed, &c.SHA256, &meta, &source, &from, &job, &by, &at); err != nil {
		return c, err
	}
	c.Source, c.FromRevision, c.JobID, c.By, c.At = model.ConfigSource(source), int(from.Int64), job.Int64, by.Int64, fromUnix(at)
	return c, json.Unmarshal([]byte(meta), &c.Meta)
}

func (d *DB) AddConfig(ctx context.Context, c *model.ServerConfig, seal func(int) ([]byte, error)) error {
	meta, err := json.Marshal(c.Meta)
	if err != nil {
		return err
	}
	return d.tx(ctx, func(t *sql.Tx) error {
		var rev int
		if err := t.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision), 0) + 1 FROM server_configs WHERE server_id = ?`, c.ServerID).Scan(&rev); err != nil {
			return err
		}
		sealed, err := seal(rev)
		if err != nil {
			return err
		}
		res, err := t.ExecContext(ctx, `INSERT INTO server_configs (server_id, revision, config, sha256, meta, source, from_revision, job_id, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			c.ServerID, rev, sealed, c.SHA256, string(meta), string(c.Source), nullID(int64(c.FromRevision)), nullID(c.JobID), nullID(c.By), unixTime(c.At))
		if err != nil {
			return err
		}
		c.ID, _ = res.LastInsertId()
		c.Revision, c.Sealed = rev, sealed
		return nil
	})
}

func (d *DB) CurrentConfig(ctx context.Context, serverID int64) (model.ServerConfig, error) {
	c, err := scanConfig(d.db.QueryRowContext(ctx, `SELECT `+configCols+` FROM server_configs WHERE server_id = ? ORDER BY revision DESC LIMIT 1`, serverID))
	return c, notFound(err)
}

func (d *DB) ConfigRevision(ctx context.Context, serverID int64, revision int) (model.ServerConfig, error) {
	c, err := scanConfig(d.db.QueryRowContext(ctx, `SELECT `+configCols+` FROM server_configs WHERE server_id = ? AND revision = ?`, serverID, revision))
	return c, notFound(err)
}

func (d *DB) ListConfigs(ctx context.Context, serverID int64) ([]model.ServerConfig, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+configCols+` FROM server_configs WHERE server_id = ? ORDER BY revision DESC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ServerConfig
	for rows.Next() {
		c, err := scanConfig(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) SetInstallation(ctx context.Context, in model.Installation) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO installations (server_id, binary_path, config_path, unit, service_user, version, managed, binary_sha256, unit_sha256, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id) DO UPDATE SET binary_path = excluded.binary_path, config_path = excluded.config_path, unit = excluded.unit,
			service_user = excluded.service_user, version = excluded.version, managed = excluded.managed,
			binary_sha256 = excluded.binary_sha256, unit_sha256 = excluded.unit_sha256, updated_at = excluded.updated_at`,
		in.ServerID, in.Binary, in.Config, in.Unit, in.User, in.Version, in.Managed, in.BinarySHA256, in.UnitSHA256, unixTime(in.At))
	return err
}

func (d *DB) Installation(ctx context.Context, serverID int64) (model.Installation, error) {
	var in model.Installation
	var at int64
	err := d.db.QueryRowContext(ctx, `SELECT server_id, binary_path, config_path, unit, service_user, version, managed, binary_sha256, unit_sha256, updated_at,
		firewall_tool, firewall_ports, firewall_keep FROM installations WHERE server_id = ?`, serverID).
		Scan(&in.ServerID, &in.Binary, &in.Config, &in.Unit, &in.User, &in.Version, &in.Managed, &in.BinarySHA256, &in.UnitSHA256, &at,
			&in.Firewall.Tool, &in.Firewall.Ports, &in.Firewall.Keep)
	in.At = fromUnix(at)
	return in, notFound(err)
}

func (d *DB) SetFirewall(ctx context.Context, serverID int64, fw model.Firewall) error {
	res, err := d.db.ExecContext(ctx, `UPDATE installations SET firewall_tool = ?, firewall_ports = ?, firewall_keep = ? WHERE server_id = ?`,
		fw.Tool, fw.Ports, fw.Keep, serverID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
