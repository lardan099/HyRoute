package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlitelib "modernc.org/sqlite/lib"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// querier is a *sql.DB or a *sql.Tx.
type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

// loadChains reads the chains with their nodes and links, by name; id 0:
// all of them.
func loadChains(ctx context.Context, q querier, id int64) ([]model.Chain, error) {
	where := ""
	var args []any
	if id != 0 {
		where, args = ` WHERE id = ?`, []any{id}
	}
	rows, err := q.QueryContext(ctx, `SELECT id, name, notes, created_by, created_at, updated_at FROM chains`+where+` ORDER BY name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	var cs []model.Chain
	at := map[int64]int{}
	for rows.Next() {
		var c model.Chain
		var by sql.NullInt64
		var created, updated int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Notes, &by, &created, &updated); err != nil {
			rows.Close()
			return nil, err
		}
		c.CreatedBy, c.CreatedAt, c.UpdatedAt = by.Int64, fromUnix(created), fromUnix(updated)
		at[c.ID] = len(cs)
		cs = append(cs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(cs) == 0 {
		return cs, err
	}

	where = ""
	if id != 0 {
		where = ` WHERE chain_id = ?`
	}
	rows, err = q.QueryContext(ctx, `SELECT chain_id, idx, server_id FROM chain_nodes`+where+` ORDER BY chain_id, idx`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var chain, server int64
		var idx int
		if err := rows.Scan(&chain, &idx, &server); err != nil {
			rows.Close()
			return nil, err
		}
		if i, ok := at[chain]; ok {
			cs[i].Nodes = append(cs[i].Nodes, server)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = q.QueryContext(ctx, `SELECT chain_id, idx, params, state, from_revision, to_revision, config_sha256, updated_at FROM chain_links`+where+` ORDER BY chain_id, idx`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var l model.ChainLink
		var params, state string
		var updated int64
		if err := rows.Scan(&l.ChainID, &l.Idx, &params, &state, &l.FromRevision, &l.ToRevision, &l.ConfigSHA256, &updated); err != nil {
			return nil, err
		}
		l.Params, l.State, l.UpdatedAt = []byte(params), model.LinkState(state), fromUnix(updated)
		i, ok := at[l.ChainID]
		if !ok {
			continue
		}
		if n := cs[i].Nodes; l.Idx+1 < len(n) {
			l.From, l.To = n[l.Idx], n[l.Idx+1]
		}
		cs[i].Links = append(cs[i].Links, l)
	}
	return cs, rows.Err()
}

func (d *DB) CreateChain(ctx context.Context, c *model.Chain, check func(existing []model.Chain) error) error {
	if len(c.Nodes) < 2 || len(c.Links) != len(c.Nodes)-1 {
		return fmt.Errorf("chain: %d nodes and %d links", len(c.Nodes), len(c.Links))
	}
	return d.tx(ctx, func(t *sql.Tx) error {
		existing, err := loadChains(ctx, t, 0)
		if err != nil {
			return err
		}
		if check != nil {
			if err := check(existing); err != nil {
				return err
			}
		}
		res, err := t.ExecContext(ctx, `INSERT INTO chains (name, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			c.Name, c.Notes, nullID(c.CreatedBy), unixTime(c.CreatedAt), unixTime(c.UpdatedAt))
		if err != nil {
			return conflict(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for i, server := range c.Nodes {
			if _, err := t.ExecContext(ctx, `INSERT INTO chain_nodes (chain_id, idx, server_id) VALUES (?, ?, ?)`, id, i, server); err != nil {
				return nodeErr(err)
			}
		}
		links := make([]model.ChainLink, len(c.Links))
		for i, l := range c.Links {
			params := string(l.Params)
			if params == "" {
				params = "{}"
			}
			if _, err := t.ExecContext(ctx, `INSERT INTO chain_links (chain_id, idx, params, state, updated_at) VALUES (?, ?, ?, ?, ?)`,
				id, i, params, model.LinkNew, unixTime(c.CreatedAt)); err != nil {
				return err
			}
			links[i] = model.ChainLink{ChainID: id, Idx: i, From: c.Nodes[i], To: c.Nodes[i+1], Params: []byte(params), State: model.LinkNew, UpdatedAt: c.CreatedAt}
		}
		if err := syncRoles(ctx, t, c.Nodes, c.CreatedAt); err != nil {
			return err
		}
		c.ID, c.Links = id, links
		return nil
	})
}

// nodeErr: a node that names no server is store.ErrNotFound.
func nodeErr(err error) error {
	var e *sqlite3.Error
	if errors.As(err, &e) && e.Code() == sqlitelib.SQLITE_CONSTRAINT_FOREIGNKEY {
		return store.ErrNotFound
	}
	return conflict(err)
}

// syncRoles sets the role of each server from its place in the chains:
// entry, relay or exit (checks keep a server to one of them; should it
// still have several, the first of entry, relay, exit wins), standalone
// in none.
func syncRoles(ctx context.Context, t *sql.Tx, servers []int64, at time.Time) error {
	for _, id := range servers {
		rows, err := t.QueryContext(ctx, `SELECT n.idx, (SELECT COUNT(*) FROM chain_nodes m WHERE m.chain_id = n.chain_id) FROM chain_nodes n WHERE n.server_id = ?`, id)
		if err != nil {
			return err
		}
		has := map[model.ServerRole]bool{}
		for rows.Next() {
			var idx, n int
			if err := rows.Scan(&idx, &n); err != nil {
				rows.Close()
				return err
			}
			has[model.NodeRole(idx, n)] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		role := model.RoleStandalone
		for _, r := range []model.ServerRole{model.RoleExit, model.RoleRelay, model.RoleEntry} {
			if has[r] {
				role = r
			}
		}
		if _, err := t.ExecContext(ctx, `UPDATE servers SET role = ?, updated_at = ? WHERE id = ? AND role <> ?`, role, unixTime(at), id, role); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) UpdateChain(ctx context.Context, id int64, name, notes string, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE chains SET name = ?, notes = ?, updated_at = ? WHERE id = ?`, name, notes, unixTime(at), id)
	if err != nil {
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) DeleteChain(ctx context.Context, id int64, at time.Time) error {
	return d.tx(ctx, func(t *sql.Tx) error {
		cs, err := loadChains(ctx, t, id)
		if err != nil {
			return err
		}
		if len(cs) == 0 {
			return store.ErrNotFound
		}
		if _, err := t.ExecContext(ctx, `DELETE FROM chains WHERE id = ?`, id); err != nil {
			return err
		}
		return syncRoles(ctx, t, cs[0].Nodes, at)
	})
}

func (d *DB) ChainByID(ctx context.Context, id int64) (model.Chain, error) {
	cs, err := loadChains(ctx, d.db, id)
	if err != nil {
		return model.Chain{}, err
	}
	if len(cs) == 0 {
		return model.Chain{}, store.ErrNotFound
	}
	return cs[0], nil
}

func (d *DB) ListChains(ctx context.Context) ([]model.Chain, error) {
	return loadChains(ctx, d.db, 0)
}

func (d *DB) UpdateLink(ctx context.Context, l model.ChainLink) error {
	if !l.State.Valid() {
		return fmt.Errorf("link state %q", l.State)
	}
	params := string(l.Params)
	if params == "" {
		params = "{}"
	}
	res, err := d.db.ExecContext(ctx, `UPDATE chain_links SET params = ?, state = ?, from_revision = ?, to_revision = ?, config_sha256 = ?, updated_at = ? WHERE chain_id = ? AND idx = ?`,
		params, l.State, l.FromRevision, l.ToRevision, l.ConfigSHA256, unixTime(l.UpdatedAt), l.ChainID, l.Idx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) SetLinkSecrets(ctx context.Context, chainID int64, idx int, sealed []byte, at time.Time) error {
	res, err := d.db.ExecContext(ctx, `UPDATE chain_links SET secrets = ?, updated_at = ? WHERE chain_id = ? AND idx = ?`, sealed, unixTime(at), chainID, idx)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) LinkSecrets(ctx context.Context, chainID int64, idx int) ([]byte, error) {
	var b []byte
	err := d.db.QueryRowContext(ctx, `SELECT secrets FROM chain_links WHERE chain_id = ? AND idx = ?`, chainID, idx).Scan(&b)
	return b, notFound(err)
}
