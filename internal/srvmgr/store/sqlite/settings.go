package sqlite

import (
	"context"
	"time"
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
