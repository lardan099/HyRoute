package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const serverCols = `id, name, tags, country, location, host, ssh_port, ssh_user, auth_type, role, notes, state, created_at, updated_at, hop_interval`

func scanServer(r rowScanner) (model.Server, error) {
	var s model.Server
	var tags, auth, role, state string
	var created, updated int64
	err := r.Scan(&s.ID, &s.Name, &tags, &s.Country, &s.Location, &s.Host, &s.SSHPort, &s.SSHUser, &auth, &role, &s.Notes, &state, &created, &updated, &s.HopInterval)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal([]byte(tags), &s.Tags); err != nil {
		return s, err
	}
	s.AuthType, s.Role, s.State = model.AuthType(auth), model.ServerRole(role), model.ServerState(state)
	s.CreatedAt, s.UpdatedAt = fromUnix(created), fromUnix(updated)
	return s, nil
}

func tagsJSON(tags []string) string {
	if tags == nil {
		tags = []string{}
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

func putCredentials(ctx context.Context, t *sql.Tx, id int64, seal store.SealFunc, at time.Time) error {
	if seal == nil {
		return nil
	}
	creds, err := seal(id)
	if err != nil {
		return err
	}
	for _, c := range creds {
		if _, err := t.ExecContext(ctx, `INSERT INTO server_credentials (server_id, kind, sealed, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (server_id, kind) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at`,
			id, string(c.Kind), c.Sealed, unixTime(at)); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) CreateServer(ctx context.Context, s *model.Server, seal store.SealFunc) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		res, err := t.ExecContext(ctx, `INSERT INTO servers (name, tags, country, location, host, ssh_port, ssh_user, auth_type, role, notes, state, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			s.Name, tagsJSON(s.Tags), s.Country, s.Location, s.Host, s.SSHPort, s.SSHUser, string(s.AuthType), string(s.Role), s.Notes, string(s.State), unixTime(s.CreatedAt), unixTime(s.UpdatedAt))
		if err != nil {
			return conflict(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		if err := putCredentials(ctx, t, id, seal, s.UpdatedAt); err != nil {
			return err
		}
		s.ID = id
		return nil
	})
}

// busy fails with ErrBusy when the server has an unfinished job.
func busy(ctx context.Context, t *sql.Tx, id int64) error {
	var n int
	if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE server_id = ? AND `+unfinished, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return store.ErrBusy
	}
	return nil
}

func (d *DB) UpdateServer(ctx context.Context, s *model.Server, seal store.SealFunc, drop []model.CredKind) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		var host, user, authType string
		var port int
		err := t.QueryRowContext(ctx, `SELECT host, ssh_port, ssh_user, auth_type FROM servers WHERE id = ?`, s.ID).Scan(&host, &port, &user, &authType)
		if err != nil {
			return notFound(err)
		}
		var creds []model.Credential
		if seal != nil {
			if creds, err = seal(s.ID); err != nil {
				return err
			}
		}
		moved := host != s.Host || port != s.SSHPort
		if moved || user != s.SSHUser || authType != string(s.AuthType) || len(creds) > 0 {
			if err := busy(ctx, t, s.ID); err != nil {
				return err
			}
		}
		res, err := t.ExecContext(ctx, `UPDATE servers SET name = ?, tags = ?, country = ?, location = ?, host = ?, ssh_port = ?, ssh_user = ?, auth_type = ?, role = ?, notes = ?, state = ?, updated_at = ? WHERE id = ?`,
			s.Name, tagsJSON(s.Tags), s.Country, s.Location, s.Host, s.SSHPort, s.SSHUser, string(s.AuthType), string(s.Role), s.Notes, string(s.State), unixTime(s.UpdatedAt), s.ID)
		if err != nil {
			return conflict(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		for _, k := range drop {
			if _, err := t.ExecContext(ctx, `DELETE FROM server_credentials WHERE server_id = ? AND kind = ?`, s.ID, string(k)); err != nil {
				return err
			}
		}
		// Another address is another machine: its host key must be
		// confirmed again rather than compared with the old one.
		if moved {
			if _, err := t.ExecContext(ctx, `DELETE FROM host_keys WHERE server_id = ?`, s.ID); err != nil {
				return err
			}
		}
		return putCredentials(ctx, t, s.ID, func(int64) ([]model.Credential, error) { return creds, nil }, s.UpdatedAt)
	})
}

func (d *DB) SetHopInterval(ctx context.Context, id int64, seconds int, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE servers SET hop_interval = ?, updated_at = ? WHERE id = ?`, seconds, unixTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) SetServerState(ctx context.Context, id int64, state model.ServerState, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE servers SET state = ?, updated_at = ? WHERE id = ?`, string(state), unixTime(at), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) SwapServerState(ctx context.Context, id int64, from []model.ServerState, state model.ServerState, at time.Time) (bool, error) {
	if len(from) == 0 {
		return false, nil
	}
	args := []any{string(state), unixTime(at), id}
	marks := make([]string, len(from))
	for i, f := range from {
		marks[i] = "?"
		args = append(args, string(f))
	}
	res, err := d.db.ExecContext(ctx, `UPDATE servers SET state = ?, updated_at = ? WHERE id = ? AND state IN (`+strings.Join(marks, ", ")+`)`, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (d *DB) DeleteServer(ctx context.Context, id int64) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		if err := busy(ctx, t, id); err != nil {
			return err
		}
		var chains int
		if err := t.QueryRowContext(ctx, `SELECT COUNT(*) FROM chain_nodes WHERE server_id = ?`, id).Scan(&chains); err != nil {
			return err
		}
		if chains > 0 {
			return store.ErrInChain
		}
		res, err := t.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return store.ErrNotFound
		}
		return nil
	})
}

func (d *DB) ServerByID(ctx context.Context, id int64) (model.Server, error) {
	s, err := scanServer(d.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE id = ?`, id))
	return s, notFound(err)
}

func (d *DB) ListServers(ctx context.Context) ([]model.Server, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+serverCols+` FROM servers ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ss []model.Server
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, err
		}
		ss = append(ss, s)
	}
	return ss, rows.Err()
}

func (d *DB) ServerCredentials(ctx context.Context, id int64) ([]model.Credential, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT kind, sealed FROM server_credentials WHERE server_id = ? ORDER BY kind`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var cs []model.Credential
	for rows.Next() {
		var c model.Credential
		var kind string
		if err := rows.Scan(&kind, &c.Sealed); err != nil {
			return nil, err
		}
		c.Kind = model.CredKind(kind)
		cs = append(cs, c)
	}
	return cs, rows.Err()
}
