package reconcile

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/deploy"
	"github.com/lardan099/hyroute/internal/srvmgr/geo"
	"github.com/lardan099/hyroute/internal/srvmgr/importer"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/service"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// CannotRevertError: HyRoute has no job that puts its version of the
// thing back; Msg says why, for people.
type CannotRevertError struct{ Msg string }

func (e *CannotRevertError) Error() string { return e.Msg }

// ErrUnreadable: the config on the server is not YAML, so it cannot be
// masked: no diff is shown.
var ErrUnreadable = errors.New("reconcile: the config on the server is not YAML")

// item is the server's result and its difference with key (ErrGone: none).
func (r *Reconciler) item(ctx context.Context, serverID int64, key string) (model.Drift, model.DriftItem, error) {
	d, err := r.Store.Drift(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return d, model.DriftItem{}, ErrGone
	} else if err != nil {
		return d, model.DriftItem{}, err
	}
	it, ok := d.Item(key)
	if !ok {
		return d, it, ErrGone
	}
	return d, it, nil
}

// isHysteria: the program is named hysteria*, as maintenance requires.
func isHysteria(p string) bool { return strings.HasPrefix(path.Base(p), "hysteria") }

// Revertible reports whether HyRoute can put its version of difference it
// back on a server with installation in, and why not.
func (r *Reconciler) Revertible(in model.Installation, it model.DriftItem) (bool, string) {
	if r.Jobs == nil {
		return false, "Возврат версии HyRoute здесь недоступен."
	}
	switch it.Kind {
	case model.DriftUnit:
		if !in.Managed {
			return false, "Службу установил не HyRoute: вернуть свою версию ему нечего, её можно только принять."
		}
	case model.DriftBinary:
		if !isHysteria(in.Binary) {
			return false, "Служба запускает не hysteria*: HyRoute эту программу не заменяет."
		}
		if !in.Managed && in.Version == "" {
			return false, "Версия Hysteria неизвестна: HyRoute не знает, какой релиз поставить. Примите бинарник или обновите Hysteria в «Обслуживании»."
		}
	}
	return true, ""
}

// Accept takes what is on the server as HyRoute's for difference key
// («Принять как новую ревизию»): the config becomes a revision with
// source external (it must still be the config found, and parse), the
// other things get their hashes recorded as found (a link then counts as
// stale until it is deployed again). It reads the server again over a
// read-only connection and changes nothing there. It returns the result
// without the difference; the server needs no attention once none is
// left.
func (r *Reconciler) Accept(ctx context.Context, serverID int64, key string, actor int64) (model.Drift, error) {
	r.defaults()
	unlock := r.lock(serverID)
	defer unlock()
	if _, busy, err := r.newestJob(ctx, serverID); err != nil {
		return model.Drift{}, err
	} else if busy {
		return model.Drift{}, store.ErrBusy
	}
	d, it, err := r.item(ctx, serverID, key)
	if err != nil {
		return d, err
	}
	srv, err := r.Store.ServerByID(ctx, serverID)
	if err != nil {
		return d, err
	}
	cctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	o, close, err := r.open(cctx, srv)
	if err != nil {
		return d, err
	}
	defer close()
	details := "what=" + key
	switch it.Kind {
	case model.DriftConfig:
		var rev int
		if rev, err = r.acceptConfig(cctx, o, it, actor); err == nil {
			details += fmt.Sprintf(" revision=%d", rev)
		}
	case model.DriftUnit:
		err = r.acceptInstallation(cctx, o, it)
	case model.DriftBinary:
		err = r.acceptInstallation(cctx, o, it)
	case model.DriftGeo:
		err = r.acceptGeo(cctx, o, it)
	case model.DriftLink:
		err = r.acceptLink(cctx, o, it)
	default:
		err = ErrGone
	}
	if err != nil {
		return d, err
	}
	if err := r.Store.AddAudit(ctx, model.AuditEntry{Time: r.Now(), UserID: actor, Action: "drift_accepted", Target: fmt.Sprintf("server/%d", serverID), Details: details}); err != nil {
		r.Log.Warn("reconcile: audit", "err", err)
	}
	d = r.without(ctx, d, key)
	if err := r.Store.SetDrift(ctx, d); err != nil {
		return d, err
	}
	r.resolved(ctx, serverID, key)
	return d, nil
}

// without is d without difference key; the server needs attention no
// more when it was the last one.
func (r *Reconciler) without(ctx context.Context, d model.Drift, key string) model.Drift {
	d.Items = slices.DeleteFunc(slices.Clone(d.Items), func(it model.DriftItem) bool { return it.Key == key })
	if key == model.DriftKey(model.DriftConfig, 0, 0) {
		d.Config = nil
	}
	if len(d.Items) == 0 {
		r.release(ctx, &d)
	}
	return d
}

// acceptConfig stores the config on the server as a revision (source
// external) and returns its number.
func (r *Reconciler) acceptConfig(ctx context.Context, o on, it model.DriftItem, actor int64) (int, error) {
	cur, err := r.Store.CurrentConfig(ctx, o.srv.ID)
	if err != nil {
		return 0, err
	}
	if cur.Revision != it.Revision {
		return 0, ErrChanged // HyRoute stored another revision since
	}
	want := it.Files[0].Got
	if want == "" {
		return 0, &model.FieldError{Field: "config", Msg: "Конфига на сервере нет: принимать нечего. Верните версию HyRoute."}
	}
	got, raw, err := readConfig(ctx, o)
	if err != nil {
		return 0, err
	}
	if got != want {
		return 0, ErrChanged
	}
	c, err := hyconfig.ParseServer(raw)
	if err != nil {
		return 0, &model.FieldError{Field: "config", Msg: "Конфиг на сервере не разобрать, ревизией он стать не может: " + redact.String(err.Error())}
	}
	meta, err := importer.ConfigMeta(ctx, o.ro, c, o.in.Version, o.su, r.Now())
	if err != nil {
		return 0, err
	}
	rev := model.ServerConfig{ServerID: o.srv.ID, SHA256: got, Meta: meta, Source: model.ConfigExternal, By: actor, At: r.Now()}
	if err := r.Store.AddConfig(ctx, &rev, func(n int) ([]byte, error) { return r.Keys.Seal(raw, model.ConfigContext(o.srv.ID, n)) }); err != nil {
		return 0, err
	}
	return rev.Revision, nil
}

// acceptInstallation records the unit or the binary as found (a binary
// that is Hysteria with its version).
func (r *Reconciler) acceptInstallation(ctx context.Context, o on, it model.DriftItem) error {
	in := o.in
	want := it.Files[0].Got
	var got string
	var err error
	if it.Kind == model.DriftUnit {
		got, _, err = remote.UnitSHA256(ctx, o.ro, in.Unit, o.su)
	} else {
		got, err = remote.FileSHA256(ctx, o.ro, in.Binary, o.su)
	}
	if err != nil {
		return err
	}
	if got != want {
		return ErrChanged
	}
	if it.Kind == model.DriftUnit {
		in.UnitSHA256 = got
	} else {
		in.BinarySHA256 = got
		if got != "" && isHysteria(in.Binary) {
			if v, err := remote.HysteriaVersion(ctx, o.ro, in.Binary); err == nil && v != "" {
				in.Version = v
			}
		}
	}
	in.At = r.Now()
	return r.Store.SetInstallation(ctx, in)
}

// acceptGeo records the databases as found.
func (r *Reconciler) acceptGeo(ctx context.Context, o on, it model.DriftItem) error {
	g, err := r.Store.ServerGeo(ctx, o.srv.ID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrGone
	} else if err != nil {
		return err
	}
	for _, f := range it.Files {
		got, err := remote.FileSHA256(ctx, o.ro, f.Path, o.su)
		if err != nil {
			return err
		}
		if got != f.Got {
			return ErrChanged
		}
		switch path.Base(f.Path) {
		case geo.GeoIP:
			g.GeoIP = got
		case geo.GeoSite:
			g.GeoSite = got
		}
	}
	g.JobID, g.At = 0, r.Now()
	return r.Store.SetServerGeo(ctx, g)
}

// acceptLink records the link's client config and unit as found.
func (r *Reconciler) acceptLink(ctx context.Context, o on, it model.DriftItem) error {
	c, err := r.Store.ChainByID(ctx, it.Chain)
	if errors.Is(err, store.ErrNotFound) {
		return ErrGone
	} else if err != nil {
		return err
	}
	if it.Idx >= len(c.Links) {
		return ErrGone
	}
	l := c.Links[it.Idx]
	if l.From != o.srv.ID || (l.State != model.LinkActive && l.State != model.LinkStale) {
		return ErrGone
	}
	diff, _, err := linkFiles(ctx, o, c.ID, l)
	if err != nil {
		return err
	}
	if !slices.Equal(diff, it.Files) {
		return ErrChanged
	}
	for _, f := range it.Files {
		if strings.HasSuffix(f.Path, ".service") {
			l.UnitSHA256 = f.Got
		} else {
			l.ConfigSHA256 = f.Got
		}
	}
	l.UpdatedAt = r.Now()
	return r.Store.UpdateLink(ctx, l)
}

// Revert queues the job that puts HyRoute's version of difference key
// back («Вернуть версию HyRoute»): the apply job with the current
// revision for the config, the maintenance job for the unit and the
// binary (a reinstall of HyRoute's installation, else an upgrade to the
// recorded version), the geo job, the link job. Each has its usual
// checks, backup and rollback. Once the job completes the server is
// checked again, and the difference goes away when it is gone.
func (r *Reconciler) Revert(ctx context.Context, serverID int64, key string, actor int64) (model.Job, error) {
	r.defaults()
	unlock := r.lock(serverID)
	defer unlock()
	d, it, err := r.item(ctx, serverID, key)
	if err != nil {
		return model.Job{}, err
	}
	in, err := r.Store.Installation(ctx, serverID)
	if err != nil {
		return model.Job{}, err
	}
	if ok, why := r.Revertible(in, it); !ok {
		return model.Job{}, &CannotRevertError{Msg: why}
	}
	var j model.Job
	switch it.Kind {
	case model.DriftConfig:
		j, err = r.Jobs.RevertConfig(ctx, serverID, it.Files[0].Got, actor)
	case model.DriftUnit:
		j, err = r.Jobs.Maintain(ctx, serverID, deploy.OpReinstall, "", actor)
	case model.DriftBinary:
		if in.Managed {
			j, err = r.Jobs.Maintain(ctx, serverID, deploy.OpReinstall, "", actor)
		} else {
			j, err = r.Jobs.Maintain(ctx, serverID, deploy.OpUpgrade, in.Version, actor)
		}
	case model.DriftGeo:
		j, err = r.Jobs.InstallGeo(ctx, serverID, actor)
	case model.DriftLink:
		j, err = r.Jobs.Relink(ctx, it.Chain, it.Idx, actor)
	default:
		err = ErrGone
	}
	if err != nil {
		return j, err
	}
	for i := range d.Items {
		if d.Items[i].Key == key {
			d.Items[i].Job = j.ID
		}
	}
	if !d.AttentionAt.IsZero() {
		d.Reverts = append(d.Reverts, j.ID)
	}
	if err := r.Store.SetDrift(ctx, d); err != nil {
		r.Log.Warn("reconcile: store", "err", err) // the job is queued all the same
	}
	r.await(j.ID, serverID)
	return j, nil
}

// maxWatch bounds the watch of a revert job (a job queued behind others
// on a server that does not answer); the next round covers it then.
const maxWatch = 6 * time.Hour

// await checks the server again once revert job jobID completes.
func (r *Reconciler) await(jobID, serverID int64) {
	ctx, cancel := context.WithTimeout(r.background(), maxWatch)
	go func() {
		defer cancel()
		t := time.NewTicker(r.Poll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			j, err := r.Store.JobByID(ctx, jobID)
			if errors.Is(err, store.ErrNotFound) {
				return
			}
			if err != nil || !j.State.Terminal() {
				continue
			}
			if j.State == model.JobCompleted {
				if _, err := r.Check(ctx, serverID); err != nil && !errors.Is(err, store.ErrBusy) && ctx.Err() == nil {
					r.Log.Warn("reconcile: check after a revert", "job", jobID, "err", err)
				}
			}
			return
		}
	}()
}

// ConfigDiff is the difference between the revision and the config found
// on the server, masked as the config editor masks it: the diff and the
// paths of the secrets that differ (nil, nil when the config is gone from
// the server). The secrets of both configs are hidden wherever else they
// show too. ErrUnreadable: the config found is not YAML.
func (r *Reconciler) ConfigDiff(ctx context.Context, serverID int64) ([]apply.Line, []string, error) {
	d, it, err := r.item(ctx, serverID, model.DriftKey(model.DriftConfig, 0, 0))
	if err != nil {
		return nil, nil, err
	}
	if d.Config == nil {
		return nil, nil, nil
	}
	rev, err := r.Store.ConfigRevision(ctx, serverID, it.Revision)
	if err != nil {
		return nil, nil, err
	}
	before, err := r.Keys.Open(rev.Sealed, model.ConfigContext(serverID, rev.Revision))
	if err != nil {
		return nil, nil, err
	}
	after, err := r.Keys.Open(d.Config, model.DriftContext(serverID))
	if err != nil {
		return nil, nil, err
	}
	lines, secrets, err := apply.CompareConfigs(before, after)
	if err != nil {
		return nil, nil, ErrUnreadable
	}
	red := redact.New()
	for _, b := range [][]byte{before, after} {
		if c, err := hyconfig.ParseServer(b); err == nil {
			red.Add(service.ConfigSecrets(c)...)
		}
	}
	for i := range lines {
		lines[i].Text = red.String(lines[i].Text)
	}
	return lines, secrets, nil
}
