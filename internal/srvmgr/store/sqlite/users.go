package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
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

const userCols = `id, username, password_hash, role, disabled, created_at, updated_at, last_login_at`

func scanUser(r rowScanner) (model.User, error) {
	var u model.User
	var created, updated, login int64
	var role string
	err := r.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.Disabled, &created, &updated, &login)
	u.Role = model.Role(role)
	u.CreatedAt, u.UpdatedAt, u.LastLoginAt = fromUnix(created), fromUnix(updated), fromUnix(login)
	return u, err
}

func insertUser(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, u *model.User) error {
	res, err := q.ExecContext(ctx, `INSERT INTO users (username, password_hash, role, disabled, created_at, updated_at, last_login_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, string(u.Role), u.Disabled, unixTime(u.CreatedAt), unixTime(u.UpdatedAt), unixTime(u.LastLoginAt))
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
	return listUsers(ctx, d.db)
}

func listUsers(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) ([]model.User, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY id`)
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

func (d *DB) SetLastLogin(ctx context.Context, id int64, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, unixTime(at), id)
	return err
}

func (d *DB) ChangeUsers(ctx context.Context, at time.Time, change func(all []model.User) ([]model.User, []int64, error)) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		all, err := listUsers(ctx, t)
		if err != nil {
			return err
		}
		changed, revoke, err := change(all)
		if err != nil {
			return err
		}
		for _, u := range changed {
			res, err := t.ExecContext(ctx, `UPDATE users SET role = ?, disabled = ?, password_hash = ?, updated_at = ? WHERE id = ?`,
				string(u.Role), u.Disabled, u.PasswordHash, unixTime(at), u.ID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return store.ErrNotFound
			}
		}
		for _, id := range revoke {
			if _, err := t.ExecContext(ctx, `UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, unixTime(at), id); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *DB) DeleteUser(ctx context.Context, id int64, check func(all []model.User) error) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		all, err := listUsers(ctx, t)
		if err != nil {
			return err
		}
		if err := check(all); err != nil {
			return err
		}
		// Sessions go with the user (ON DELETE CASCADE); what the user made
		// stays without its author (ON DELETE SET NULL).
		res, err := t.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
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

func (d *DB) TrimAudit(ctx context.Context, actions []string, keep int) error {
	if len(actions) == 0 {
		return nil
	}
	in := strings.Repeat(",?", len(actions))[1:]
	var args []any
	for range 2 {
		for _, a := range actions {
			args = append(args, a)
		}
	}
	// The id of the newest entry beyond keep; NULL (nothing deleted) when
	// there are no more than keep.
	_, err := d.db.ExecContext(ctx, `DELETE FROM audit_log WHERE action IN (`+in+`) AND id <= (
		SELECT id FROM audit_log WHERE action IN (`+in+`) ORDER BY id DESC LIMIT 1 OFFSET ?)`, append(args, keep)...)
	return err
}

func (d *DB) ListAudit(ctx context.Context, limit int) ([]model.AuditEntry, error) {
	return d.queryAudit(ctx, `SELECT id, ts, user_id, action, target, details FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
}

func (d *DB) QueryAudit(ctx context.Context, f model.AuditFilter) ([]model.AuditEntry, error) {
	var where []string
	var args []any
	if f.UserID != 0 {
		where, args = append(where, "user_id = ?"), append(args, f.UserID)
	}
	if len(f.Actions) > 0 {
		where = append(where, "action IN ("+strings.Repeat(",?", len(f.Actions))[1:]+")")
		for _, a := range f.Actions {
			args = append(args, a)
		}
	}
	if kind, ok := strings.CutSuffix(f.Target, "/"); ok && kind != "" {
		// A range rather than LIKE: no wildcards to escape, and the index
		// on target serves it ('0' follows '/').
		where, args = append(where, "target >= ? AND target < ?"), append(args, kind+"/", kind+"0")
	} else if f.Target != "" {
		where, args = append(where, "target = ?"), append(args, f.Target)
	}
	if !f.From.IsZero() {
		where, args = append(where, "ts >= ?"), append(args, f.From.Unix())
	}
	if !f.To.IsZero() {
		where, args = append(where, "ts < ?"), append(args, f.To.Unix())
	}
	if f.BeforeID != 0 {
		where, args = append(where, "id < ?"), append(args, f.BeforeID)
	}
	q := `SELECT id, ts, user_id, action, target, details FROM audit_log`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	return d.queryAudit(ctx, q+` ORDER BY id DESC LIMIT ?`, append(args, limit)...)
}

func (d *DB) queryAudit(ctx context.Context, q string, args ...any) ([]model.AuditEntry, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
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
