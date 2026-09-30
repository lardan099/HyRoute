package sqlite

import (
	"context"
	"database/sql"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

func (d *DB) HostKey(ctx context.Context, serverID int64) (model.HostKey, error) {
	var k model.HostKey
	var at int64
	var by sql.NullInt64
	err := d.db.QueryRowContext(ctx, `SELECT server_id, key_type, key, fingerprint, trusted_at, trusted_by FROM host_keys WHERE server_id = ?`, serverID).
		Scan(&k.ServerID, &k.Type, &k.Key, &k.Fingerprint, &at, &by)
	k.TrustedAt, k.TrustedBy = fromUnix(at), by.Int64
	return k, notFound(err)
}

func (d *DB) SetHostKey(ctx context.Context, k model.HostKey) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO host_keys (server_id, key_type, key, fingerprint, trusted_at, trusted_by) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id) DO UPDATE SET key_type = excluded.key_type, key = excluded.key, fingerprint = excluded.fingerprint, trusted_at = excluded.trusted_at, trusted_by = excluded.trusted_by`,
		k.ServerID, k.Type, k.Key, k.Fingerprint, unixTime(k.TrustedAt), sql.NullInt64{Int64: k.TrustedBy, Valid: k.TrustedBy != 0})
	return err
}

func (d *DB) DeleteHostKey(ctx context.Context, serverID int64) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM host_keys WHERE server_id = ?`, serverID)
	return err
}
