package sqlite

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// sealedColumn is a column with values sealed with the master key
// (package secrets) and how to rebuild, from the row, the context a value
// was sealed for. A new sealed column goes into sealedColumns: the master
// key check at start, the key check of the admin, the backup check and
// rekey all read this list.
type sealedColumn struct {
	table, column string
	// keys selects the two values context takes (the second may be '').
	keys    string
	context func(id int64, sub string) string
}

// sealedColumns in the order SealedSample tries them.
var sealedColumns = []sealedColumn{
	{"server_credentials", "sealed", "server_id, kind", func(id int64, kind string) string {
		return model.CredContext(id, model.CredKind(kind))
	}},
	{"server_configs", "config", "server_id, revision", func(id int64, rev string) string {
		n, _ := strconv.Atoi(rev)
		return model.ConfigContext(id, n)
	}},
	{"jobs", "secret", "id, ''", func(id int64, _ string) string { return model.JobSecretContext(id) }},
	{"chain_links", "secrets", "chain_id, idx", func(id int64, idx string) string {
		n, _ := strconv.Atoi(idx)
		return model.LinkSecretContext(id, n)
	}},
	{"alert_channels", "secret", "id, ''", func(id int64, _ string) string { return model.AlertSecretContext(id) }},
	{"drift", "config", "server_id, ''", func(id int64, _ string) string { return model.DriftContext(id) }},
}

// present are the sealed columns whose tables this database has: a
// database of an older schema (a backup being restored, one a newer
// binary reads before its first start) lacks the tables of later
// migrations, and their values cannot be there.
func (d *DB) present(ctx context.Context) ([]sealedColumn, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		tables[n] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []sealedColumn
	for _, c := range sealedColumns {
		if tables[c.table] {
			out = append(out, c)
		}
	}
	return out, nil
}

// isSealed is the SQL condition that column holds a sealed value: it
// starts with 4 bytes of magic and the key version (big-endian, see
// package secrets), and SQL reads only those 8 bytes.
func isSealed(column string) string {
	return "substr(" + column + ", 1, 4) = CAST('HRS1' AS BLOB)"
}

// HasSealed reports whether any row holds a value sealed with the master
// key.
func (d *DB) HasSealed(ctx context.Context) (bool, error) {
	cols, err := d.present(ctx)
	if err != nil || len(cols) == 0 {
		return false, err
	}
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf(`EXISTS (SELECT 1 FROM %s WHERE %s IS NOT NULL)`, c.table, c.column)
	}
	var has bool
	err = d.db.QueryRowContext(ctx, `SELECT `+strings.Join(parts, " OR ")).Scan(&has)
	return has, err
}

// SealedVersions are the master key versions the stored sealed values
// need.
func (d *DB) SealedVersions(ctx context.Context) ([]uint32, error) {
	cols, err := d.present(ctx)
	if err != nil || len(cols) == 0 {
		return nil, err
	}
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = fmt.Sprintf(`SELECT %s AS v FROM %s WHERE %s IS NOT NULL`, c.column, c.table, c.column)
	}
	rows, err := d.db.QueryContext(ctx, `SELECT DISTINCT substr(v, 5, 4) FROM (`+strings.Join(parts, " UNION ALL ")+`) WHERE `+isSealed("v"))
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
// was sealed for, to try a key on (store.ErrNotFound: there are none).
func (d *DB) SealedSample(ctx context.Context) ([]byte, string, error) {
	cols, err := d.present(ctx)
	if err != nil {
		return nil, "", err
	}
	for _, c := range cols {
		var (
			id     int64
			sub    string
			sealed []byte
		)
		err := d.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s, %s FROM %s WHERE %s IS NOT NULL ORDER BY rowid LIMIT 1`,
			c.keys, c.column, c.table, c.column)).Scan(&id, &sub, &sealed)
		switch {
		case err == nil:
			return sealed, c.context(id, sub), nil
		case !errors.Is(err, sql.ErrNoRows):
			return nil, "", err
		}
	}
	return nil, "", store.ErrNotFound
}

// SealedSamples are one sealed value of every master key version the
// stored values use, with their contexts: a key that opens them all opens
// the database.
func (d *DB) SealedSamples(ctx context.Context) ([]store.SealedValue, error) {
	cols, err := d.present(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[uint32]bool{}
	var out []store.SealedValue
	for _, c := range cols {
		rows, err := d.db.QueryContext(ctx, fmt.Sprintf(`SELECT substr(%[2]s, 5, 4), %[1]s, %[2]s FROM %[3]s WHERE %[4]s GROUP BY substr(%[2]s, 5, 4)`,
			c.keys, c.column, c.table, isSealed(c.column)))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var (
				v      []byte
				id     int64
				sub    string
				sealed []byte
			)
			if err := rows.Scan(&v, &id, &sub, &sealed); err != nil {
				rows.Close()
				return nil, err
			}
			ver := binary.BigEndian.Uint32(v)
			if !seen[ver] {
				seen[ver] = true
				out = append(out, store.SealedValue{Version: ver, Sealed: sealed, Context: c.context(id, sub)})
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// rewrapBatch bounds a transaction of RewrapSealed: rows and bytes.
const (
	rewrapRows  = 100
	rewrapBytes = 16 << 20
)

// RewrapSealed seals again every stored value that is not sealed with
// version current: rewrap gets the value and its context and returns the
// new one. Rows are rewritten in small transactions: when it stops half
// way (an error, a kill), the rows done stay done and a second run goes
// on with the rest. n counts the rewritten values.
func (d *DB) RewrapSealed(ctx context.Context, current uint32, rewrap func(sealed []byte, context string) ([]byte, error)) (n int, err error) {
	cur := binary.BigEndian.AppendUint32(nil, current)
	cols, err := d.present(ctx)
	if err != nil {
		return 0, err
	}
	for _, c := range cols {
		var ids []int64
		rows, err := d.db.QueryContext(ctx, fmt.Sprintf(`SELECT rowid FROM %s WHERE %s AND substr(%s, 5, 4) != ? ORDER BY rowid`,
			c.table, isSealed(c.column), c.column), cur)
		if err != nil {
			return n, err
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return n, err
			}
			ids = append(ids, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return n, err
		}
		for len(ids) > 0 {
			var done int
			err := d.tx(ctx, func(t *sql.Tx) error {
				size := 0
				for done < len(ids) && done < rewrapRows && size < rewrapBytes {
					var (
						id     int64
						sub    string
						sealed []byte
					)
					err := t.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s, %s FROM %s WHERE rowid = ?`, c.keys, c.column, c.table), ids[done]).Scan(&id, &sub, &sealed)
					if err != nil {
						return err
					}
					context := c.context(id, sub)
					b, err := rewrap(sealed, context)
					if err != nil {
						return fmt.Errorf("%s.%s, %s: %w", c.table, c.column, context, err)
					}
					if _, err := t.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET %s = ? WHERE rowid = ?`, c.table, c.column), b, ids[done]); err != nil {
						return err
					}
					size += len(sealed)
					done++
				}
				return nil
			})
			if err != nil {
				return n, err
			}
			n += done
			ids = ids[done:]
		}
	}
	return n, nil
}
