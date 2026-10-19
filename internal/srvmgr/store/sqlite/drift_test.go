package sqlite

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// The latest reconciliation of a server is stored whole and replaced
// whole; it goes with its server.
func TestDrift(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	ids := addServers(t, d, "a", "b")
	if _, err := d.Drift(ctx, ids[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("never checked: %v", err)
	}
	at := time.Unix(1_700_000_000, 0)
	dr := model.Drift{
		ServerID: ids[0], At: at, Checked: []string{"config", "unit"}, Skipped: []string{"binary"},
		Items: []model.DriftItem{{Key: "config", Kind: model.DriftConfig, Revision: 2, Files: []model.DriftFile{{Path: "/etc/hysteria/config.yaml", Want: "a", Got: "b"}},
			Summary: "differs", Since: at, Job: 7}},
		Config: sealedAs(1, "found"), AttentionAt: at, Reverts: []int64{7},
	}
	if err := d.SetDrift(ctx, dr); err != nil {
		t.Fatal(err)
	}
	got, err := d.Drift(ctx, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	got.Items[0].Since = got.Items[0].Since.UTC()
	dr.Items[0].Since = dr.Items[0].Since.UTC()
	if !reflect.DeepEqual(got, dr) {
		t.Fatalf("%+v\nwant %+v", got, dr)
	}
	// Replaced whole: nothing differs any more.
	clean := model.Drift{ServerID: ids[0], At: at.Add(time.Hour), Checked: []string{"config"}}
	if err := d.SetDrift(ctx, clean); err != nil {
		t.Fatal(err)
	}
	got, _ = d.Drift(ctx, ids[0])
	if got.Items == nil || len(got.Items) != 0 || got.Config != nil || !got.AttentionAt.IsZero() || len(got.Reverts) != 0 || !got.At.Equal(clean.At) {
		t.Fatalf("replaced: %+v", got)
	}
	if err := d.SetDrift(ctx, model.Drift{ServerID: ids[1], At: at, Error: "no route"}); err != nil {
		t.Fatal(err)
	}
	all, err := d.Drifts(ctx)
	if err != nil || len(all) != 2 || all[1].Error != "no route" {
		t.Fatalf("all: %+v %v", all, err)
	}
	if err := d.DeleteServer(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Drift(ctx, ids[0]); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("outlived its server: %v", err)
	}
}

// The config found on a server is a sealed column: the key checks see it
// and rekey rewraps it with its context.
func TestDriftSealed(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	ids := addServers(t, d, "a")
	if err := d.SetDrift(ctx, model.Drift{ServerID: ids[0], At: time.Now(), Config: sealedAs(4, "found")}); err != nil {
		t.Fatal(err)
	}
	if vs, err := d.SealedVersions(ctx); err != nil || !slices.Equal(vs, []uint32{4}) {
		t.Fatalf("versions %v %v", vs, err)
	}
	samples, err := d.SealedSamples(ctx)
	if err != nil || len(samples) != 1 || samples[0].Context != model.DriftContext(ids[0]) || !bytes.Equal(samples[0].Sealed, sealedAs(4, "found")) {
		t.Fatalf("samples %+v %v", samples, err)
	}
	var contexts []string
	n, err := d.RewrapSealed(ctx, 5, func(sealed []byte, c string) ([]byte, error) {
		contexts = append(contexts, c)
		return sealedAs(5, c), nil
	})
	if err != nil || n != 1 || !slices.Equal(contexts, []string{model.DriftContext(ids[0])}) {
		t.Fatalf("rewrap %d %v %q", n, err, contexts)
	}
}

// Installations keep the hashes of the binary and the unit, links the
// hash of their unit, and a revision may come from outside HyRoute.
func TestReconcileRecords(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	ids := addServers(t, d, "a", "b")
	in := model.Installation{ServerID: ids[0], Binary: "/usr/local/bin/hysteria", Config: "/etc/hysteria/config.yaml", Unit: "hysteria-server.service",
		Version: "v2.12.3", Managed: true, BinarySHA256: "bin", UnitSHA256: "unit", At: time.Unix(1_700_000_000, 0)}
	if err := d.SetInstallation(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got, err := d.Installation(ctx, ids[0]); err != nil || got != in {
		t.Fatalf("%+v %v", got, err)
	}
	c := model.ServerConfig{ServerID: ids[0], SHA256: "sum", Source: model.ConfigExternal, At: time.Now()}
	if err := d.AddConfig(ctx, &c, func(int) ([]byte, error) { return sealedAs(1, "cfg"), nil }); err != nil {
		t.Fatal(err)
	}
	if cur, err := d.CurrentConfig(ctx, ids[0]); err != nil || cur.Source != model.ConfigExternal {
		t.Fatalf("%+v %v", cur, err)
	}
	ch := twoNodes("c", ids[0], ids[1])
	if err := d.CreateChain(ctx, ch, func([]model.Chain) error { return nil }); err != nil {
		t.Fatal(err)
	}
	l := ch.Links[0]
	l.State, l.ConfigSHA256, l.UnitSHA256 = model.LinkActive, "cfg", "unit"
	if err := d.UpdateLink(ctx, l); err != nil {
		t.Fatal(err)
	}
	got, err := d.ChainByID(ctx, ch.ID)
	if err != nil || got.Links[0].UnitSHA256 != "unit" || got.Links[0].ConfigSHA256 != "cfg" {
		t.Fatalf("%+v %v", got.Links, err)
	}
}
