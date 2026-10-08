package reconcile

import (
	"context"
	"errors"
	"io/fs"

	"github.com/lardan099/hyroute/internal/srvmgr/cascade"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// found is what a check read on a server.
type found struct {
	checked, skipped []string
	items            []model.DriftItem
	// config is the config on the server while it differs from the
	// revision (nil: the same, or none there).
	config []byte
}

// on is the connection a check reads a server over.
type on struct {
	ro  remote.Executor // remote.ReadOnly: nothing else is ever run
	su  bool            // root's files through sudo
	srv model.Server
	in  model.Installation
}

// open connects to the server read-only. close ends the connection, also
// when ctx ends first: a server that went silent mid-command must not
// hold the round.
func (r *Reconciler) open(ctx context.Context, srv model.Server) (o on, close func(), err error) {
	in, err := r.Store.Installation(ctx, srv.ID)
	if err != nil {
		return o, nil, err
	}
	ex, err := r.Conn.Connect(ctx, srv.ID)
	if err != nil {
		return o, nil, err
	}
	stop := context.AfterFunc(ctx, func() { ex.Close() })
	close = func() { stop(); ex.Close() }
	o = on{ro: remote.ReadOnly(ex), srv: srv, in: in}
	p, err := remote.RunProbe(ctx, o.ro)
	if err != nil {
		close()
		return o, nil, err
	}
	if !p.Privileged() {
		close()
		return o, nil, ErrNoRoot
	}
	o.su = !p.Root
	return o, close, nil
}

// inspect compares everything HyRoute recorded about the server with
// what is there.
func (r *Reconciler) inspect(ctx context.Context, srv model.Server) (found, error) {
	f := found{checked: []string{}, skipped: []string{}}
	o, close, err := r.open(ctx, srv)
	if err != nil {
		return f, err
	}
	defer close()
	for _, step := range []func(context.Context, on, *found) error{r.config, r.unit, r.binary, r.geo, r.links} {
		if err := step(ctx, o, &f); err != nil {
			return f, err
		}
	}
	return f, nil
}

// config: the Hysteria config against the current revision.
func (r *Reconciler) config(ctx context.Context, o on, f *found) error {
	key := model.DriftKey(model.DriftConfig, 0, 0)
	cur, err := r.Store.CurrentConfig(ctx, o.srv.ID)
	if errors.Is(err, store.ErrNotFound) {
		f.skipped = append(f.skipped, key)
		return nil
	} else if err != nil {
		return err
	}
	got, raw, err := readConfig(ctx, o)
	if err != nil {
		return err
	}
	f.checked = append(f.checked, key)
	if got == cur.SHA256 {
		return nil
	}
	rev, err := r.Keys.Open(cur.Sealed, model.ConfigContext(o.srv.ID, cur.Revision))
	if err != nil {
		return err
	}
	f.items = append(f.items, model.DriftItem{Key: key, Kind: model.DriftConfig, Revision: cur.Revision,
		Files:   []model.DriftFile{{Path: o.in.Config, Want: cur.SHA256, Got: got}},
		Summary: configSummary(o.in.Config, cur.Revision, rev, raw, got == "")})
	f.config = raw
	return nil
}

// readConfig is the server's config and its SHA-256 ("" and nil: none).
func readConfig(ctx context.Context, o on) (string, []byte, error) {
	raw, err := o.ro.ReadFile(ctx, o.in.Config, o.su)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil, nil
	} else if err != nil {
		return "", nil, err
	}
	return sha(raw), raw, nil
}

// unit: the unit of the Hysteria service against the installation.
func (r *Reconciler) unit(ctx context.Context, o on, f *found) error {
	key := model.DriftKey(model.DriftUnit, 0, 0)
	if o.in.UnitSHA256 == "" {
		f.skipped = append(f.skipped, key)
		return nil
	}
	got, files, err := remote.UnitSHA256(ctx, o.ro, o.in.Unit, o.su)
	if err != nil {
		return err
	}
	f.checked = append(f.checked, key)
	if got != o.in.UnitSHA256 {
		f.items = append(f.items, model.DriftItem{Key: key, Kind: model.DriftUnit, Units: files,
			Files:   []model.DriftFile{{Path: o.in.Unit, Want: o.in.UnitSHA256, Got: got}},
			Summary: unitSummary(o.in.Unit, files, got == "")})
	}
	return nil
}

// binary: the Hysteria binary against the installation.
func (r *Reconciler) binary(ctx context.Context, o on, f *found) error {
	key := model.DriftKey(model.DriftBinary, 0, 0)
	if o.in.BinarySHA256 == "" {
		f.skipped = append(f.skipped, key)
		return nil
	}
	got, err := remote.FileSHA256(ctx, o.ro, o.in.Binary, o.su)
	if err != nil {
		return err
	}
	f.checked = append(f.checked, key)
	if got != o.in.BinarySHA256 {
		f.items = append(f.items, model.DriftItem{Key: key, Kind: model.DriftBinary,
			Files:   []model.DriftFile{{Path: o.in.Binary, Want: o.in.BinarySHA256, Got: got}},
			Summary: binarySummary(o.in.Binary, o.in.Version, got == "")})
	}
	return nil
}

// geoFiles are the databases HyRoute put on a server and their hashes.
func geoFiles(g model.ServerGeo) []model.DriftFile {
	var out []model.DriftFile
	for _, x := range []struct{ name, want string }{{geo.GeoIP, g.GeoIP}, {geo.GeoSite, g.GeoSite}} {
		if x.want != "" {
			out = append(out, model.DriftFile{Path: geo.ServerDir + "/" + x.name, Want: x.want})
		}
	}
	return out
}

// geo: the geo databases HyRoute put there against server_geo.
func (r *Reconciler) geo(ctx context.Context, o on, f *found) error {
	key := model.DriftKey(model.DriftGeo, 0, 0)
	g, err := r.Store.ServerGeo(ctx, o.srv.ID)
	if errors.Is(err, store.ErrNotFound) {
		return nil // HyRoute never put databases there
	} else if err != nil {
		return err
	}
	want := geoFiles(g)
	if len(want) == 0 {
		f.skipped = append(f.skipped, key)
		return nil
	}
	var diff []model.DriftFile
	for _, w := range want {
		if w.Got, err = remote.FileSHA256(ctx, o.ro, w.Path, o.su); err != nil {
			return err
		}
		if w.Got != w.Want {
			diff = append(diff, w)
		}
	}
	f.checked = append(f.checked, key)
	if len(diff) > 0 {
		f.items = append(f.items, model.DriftItem{Key: key, Kind: model.DriftGeo, Files: diff, Summary: geoSummary(diff, g.Release)})
	}
	return nil
}

// links: the client config and the unit of each deployed link that
// starts on the server against the link.
func (r *Reconciler) links(ctx context.Context, o on, f *found) error {
	chains, err := r.Store.ListChains(ctx)
	if err != nil {
		return err
	}
	for _, c := range chains {
		for _, l := range c.Links {
			if l.From != o.srv.ID || (l.State != model.LinkActive && l.State != model.LinkStale) {
				continue
			}
			key := model.DriftKey(model.DriftLink, c.ID, l.Idx)
			if l.ConfigSHA256 == "" && l.UnitSHA256 == "" {
				f.skipped = append(f.skipped, key)
				continue
			}
			diff, units, err := linkFiles(ctx, o, c.ID, l)
			if err != nil {
				return err
			}
			f.checked = append(f.checked, key)
			if len(diff) > 0 {
				f.items = append(f.items, model.DriftItem{Key: key, Kind: model.DriftLink, Chain: c.ID, Idx: l.Idx, Files: diff, Units: units,
					Summary: linkSummary(c.Name, l.Idx, len(c.Nodes), diff, units)})
			}
		}
	}
	return nil
}

// linkFiles are the files of link l that differ from its record (the
// unit named by the unit) and, when the unit differs, its files now.
func linkFiles(ctx context.Context, o on, chainID int64, l model.ChainLink) ([]model.DriftFile, []string, error) {
	var diff []model.DriftFile
	var units []string
	if l.ConfigSHA256 != "" {
		p := cascade.ConfigPath(o.in, chainID, l.Idx)
		got, err := remote.FileSHA256(ctx, o.ro, p, o.su)
		if err != nil {
			return nil, nil, err
		}
		if got != l.ConfigSHA256 {
			diff = append(diff, model.DriftFile{Path: p, Want: l.ConfigSHA256, Got: got})
		}
	}
	if l.UnitSHA256 != "" {
		name := cascade.UnitName(chainID, l.Idx)
		got, files, err := remote.UnitSHA256(ctx, o.ro, name, o.su)
		if err != nil {
			return nil, nil, err
		}
		if got != l.UnitSHA256 {
			diff, units = append(diff, model.DriftFile{Path: name, Want: l.UnitSHA256, Got: got}), files
		}
	}
	return diff, units, nil
}
