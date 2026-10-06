package sqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Setting is a value of the settings table (store.ErrNotFound: not set).
func (d *DB) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := d.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	return v, notFound(err)
}

// SetSetting stores a value of the settings table, replacing the old one.
func (d *DB) SetSetting(ctx context.Context, key, value string, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, unixTime(at))
	return err
}

// HasSealed reports whether any row holds a value sealed with the master
// key: an SSH credential, a config revision or a job secret.
func (d *DB) HasSealed(ctx context.Context) (bool, error) {
	var has bool
	err := d.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM server_credentials)
		OR EXISTS (SELECT 1 FROM server_configs)
		OR EXISTS (SELECT 1 FROM jobs WHERE secret IS NOT NULL)`).Scan(&has)
	return has, err
}

// SealedVersions are the master key versions the stored sealed values
// need: SSH credentials, config revisions, job and link secrets. A sealed
// value starts with 4 bytes of magic and the version (big-endian, see
// package secrets); only those 8 bytes are read.
func (d *DB) SealedVersions(ctx context.Context) ([]uint32, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT DISTINCT substr(v, 5, 4) FROM (
		SELECT sealed AS v FROM server_credentials
		UNION ALL SELECT config FROM server_configs
		UNION ALL SELECT secret FROM jobs WHERE secret IS NOT NULL
		UNION ALL SELECT secrets FROM chain_links WHERE secrets IS NOT NULL
	) WHERE substr(v, 1, 4) = CAST('HRS1' AS BLOB)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []uint32
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if len(b) == 4 {
			out = append(out, binary.BigEndian.Uint32(b))
		}
	}
	return out, rows.Err()
}

// SealedSample is one value sealed with the master key and the context it
// was sealed for, to try a key on: an SSH credential or else a config
// revision (store.ErrNotFound: there are none).
func (d *DB) SealedSample(ctx context.Context) ([]byte, string, error) {
	var (
		id     int64
		kind   string
		sealed []byte
	)
	switch err := d.db.QueryRowContext(ctx, `SELECT server_id, kind, sealed FROM server_credentials ORDER BY server_id, kind LIMIT 1`).Scan(&id, &kind, &sealed); {
	case err == nil:
		return sealed, model.CredContext(id, model.CredKind(kind)), nil
	case !errors.Is(err, sql.ErrNoRows):
		return nil, "", err
	}
	var rev int
	if err := d.db.QueryRowContext(ctx, `SELECT server_id, revision, config FROM server_configs ORDER BY id LIMIT 1`).Scan(&id, &rev, &sealed); err != nil {
		return nil, "", notFound(err)
	}
	return sealed, model.ConfigContext(id, rev), nil
}
