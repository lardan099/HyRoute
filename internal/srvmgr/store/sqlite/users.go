package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// unixTime is how times are stored: seconds since the epoch, 0 = zero time.
func unixTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

func nullUnix(t time.Time) sql.NullInt64 {
	return sql.NullInt64{Int64: unixTime(t), Valid: !t.IsZero()}
}

// notFound maps sql.ErrNoRows to store.ErrNotFound.
func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// conflict maps a unique constraint violation to store.ErrConflict.
func conflict(err error) error {
	var e *sqlite3.Error
	if errors.As(err, &e) && (e.Code() == sqlitelib.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlitelib.SQLITE_CONSTRAINT_PRIMARYKEY) {
		return store.ErrConflict
	}
	return err
}

type rowScanner interface{ Scan(...any) error }

const userCols = `id, username, password_hash, role, disabled, created_at, updated_at`

func scanUser(r rowScanner) (model.User, error) {
	var u model.User
	var created, updated int64
	var role string
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.Disabled, &created, &updated)
	u.Role = model.Role(role)
	u.CreatedAt, u.UpdatedAt = fromUnix(created), fromUnix(updated)
	return u, err
}

func insertUser(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, u *model.User) error {
	res, err := q.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, disabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, string(u.Role), u.Disabled, unixTime(u.CreatedAt), unixTime(u.UpdatedAt))
	if err != nil {
		return conflict(err)
	}
	u.ID, err = res.LastInsertId()
	return err
}

func (d *DB) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (d *DB) CreateUser(ctx context.Context, u *model.User) error {
	return insertUser(ctx, d.db, u)
}

func (d *DB) CreateFirstUser(ctx context.Context, u *model.User) error {
	// _txlock=immediate: the count and the insert see the same state even
	// with two setup requests at once.
	return d.tx(ctx, func(t *sql.Tx) error {
		var n int
		if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return store.ErrConflict
		}
		return insertUser(ctx, t, u)
	})
}

func (d *DB) UserByID(ctx context.Context, id int64) (model.User, error) {
	u, err := scanUser(d.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
	return u, notFound(err)
}

func (d *DB) UserByName(ctx context.Context, username string) (model.User, error) {
	u, err := scanUser(d.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, username))
	return u, notFound(err)
}

func (d *DB) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var us []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		us = append(us, u)
	}
	return us, rows.Err()
}

func (d *DB) UpdatePasswordHash(ctx context.Context, id int64, hash string, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, hash, unixTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) SetUserDisabled(ctx context.Context, id int64, disabled bool, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?`, disabled, unixTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

const sessionCols = `id, token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent`

func scanSession(r rowScanner) (model.Session, error) {
	var s model.Session
	var created, seen, expires int64
	var revoked sql.NullInt64
	err := r.Scan(&s.ID, &s.TokenHash, &s.UserID, &created, &seen, &expires, &revoked, &s.IP, &s.UserAgent)
	s.CreatedAt, s.LastSeenAt, s.ExpiresAt = fromUnix(created), fromUnix(seen), fromUnix(expires)
	if revoked.Valid {
		s.RevokedAt = fromUnix(revoked.Int64)
	}
	return s, err
}

func (d *DB) CreateSession(ctx context.Context, s *model.Session) error {
	res, err := d.db.ExecContext(ctx, `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, revoked_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.TokenHash, s.UserID, unixTime(s.CreatedAt), unixTime(s.LastSeenAt), unixTime(s.ExpiresAt), nullUnix(s.RevokedAt), s.IP, s.UserAgent)
	if err != nil {
		return conflict(err)
	}
	s.ID, err = res.LastInsertId()
	return err
}

func (d *DB) SessionByTokenHash(ctx context.Context, hash []byte) (model.Session, error) {
	s, err := scanSession(d.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE token_hash = ?`, hash))
	return s, notFound(err)
}

func (d *DB) SessionByID(ctx context.Context, id int64) (model.Session, error) {
	s, err := scanSession(d.db.QueryRowContext(ctx, `SELECT `+sessionCols+` FROM sessions WHERE id = ?`, id))
	return s, notFound(err)
}

func (d *DB) TouchSession(ctx context.Context, id int64, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id = ?`, unixTime(at), id)
	return err
}

func (d *DB) RevokeSession(ctx context.Context, id int64, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, unixTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) ListSessions(ctx context.Context, userID int64, now time.Time) ([]model.Session, error) {
	q := `SELECT ` + sessionCols + ` FROM sessions WHERE revoked_at IS NULL AND expires_at > ?`
	args := []any{unixTime(now)}
	if userID != 0 {
		q += ` AND user_id = ?`
		args = append(args, userID)
	}
	rows, err := d.db.QueryContext(ctx, q+` ORDER BY last_seen_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ss []model.Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		ss = append(ss, s)
	}
	return ss, rows.Err()
}

func (d *DB) DeleteSessionsBefore(ctx context.Context, t time.Time) error {
	_, err := d.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?)`, unixTime(t), unixTime(t))
	return err
}

func (d *DB) AddAudit(ctx context.Context, e model.AuditEntry) error {
	_, err := d.db.ExecContext(ctx, `INSERT INTO audit_log (ts, user_id, action, target, details) VALUES (?, ?, ?, ?, ?)`,
		unixTime(e.Time), sql.NullInt64{Int64: e.UserID, Valid: e.UserID != 0}, e.Action, e.Target, e.Details)
	return err
}

func (d *DB) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id, ts, user_id, action, target, details FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var es []model.AuditEntry
	for rows.Next() {
		var e model.AuditEntry
		var ts int64
		var uid sql.NullInt64
		if err := rows.Scan(&e.ID, &ts, &uid, &e.Action, &e.Target, &e.Details); err != nil {
			return nil, err
		}
		e.Time, e.UserID = fromUnix(ts), uid.Int64
		es = append(es, e)
	}
	return es, rows.Err()
}
