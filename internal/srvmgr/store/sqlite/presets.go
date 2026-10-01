package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

const presetCols = `id, name, config, notes, created_by, created_at, updated_at`

func scanPreset(r rowScanner) (model.Preset, error) {
	var p model.Preset
	var notes string
	var by sql.NullInt64
	var created, updated int64
	if err := r.Scan(&p.ID, &p.Name, &p.Config, &notes, &by, &created, &updated); err != nil {
		return p, err
	}
	if err := json.Unmarshal([]byte(notes), &p.Notes); err != nil {
		return p, err
	}
	p.CreatedBy, p.CreatedAt, p.UpdatedAt = by.Int64, fromUnix(created), fromUnix(updated)
	return p, nil
}

func notesJSON(n []string) string {
	if n == nil {
		n = []string{}
	}
	b, _ := json.Marshal(n)
	return string(b)
}

func (d *DB) CreatePreset(ctx context.Context, p *model.Preset) error {
	res, err := d.db.ExecContext(ctx, `INSERT INTO presets (name, config, notes, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		p.Name, p.Config, notesJSON(p.Notes), nullID(p.CreatedBy), unixTime(p.CreatedAt), unixTime(p.UpdatedAt))
	if err != nil {
		return conflict(err)
	}
	p.ID, err = res.LastInsertId()
	return err
}

func (d *DB) UpdatePreset(ctx context.Context, p model.Preset) error {
	res, err := d.db.ExecContext(ctx, `UPDATE presets SET name = ?, config = ?, notes = ?, updated_at = ? WHERE id = ?`,
		p.Name, p.Config, notesJSON(p.Notes), unixTime(p.UpdatedAt), p.ID)
	if err != nil {
		return conflict(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) DeletePreset(ctx context.Context, id int64) error {
	res, err := d.db.ExecContext(ctx, `DELETE FROM presets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (d *DB) PresetByID(ctx context.Context, id int64) (model.Preset, error) {
	p, err := scanPreset(d.db.QueryRowContext(ctx, `SELECT `+presetCols+` FROM presets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, store.ErrNotFound
	}
	return p, err
}

func (d *DB) ListPresets(ctx context.Context) ([]model.Preset, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+presetCols+` FROM presets ORDER BY name COLLATE NOCASE`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Preset
	for rows.Next() {
		p, err := scanPreset(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
