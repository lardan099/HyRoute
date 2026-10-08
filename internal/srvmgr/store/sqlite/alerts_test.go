package sqlite

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// Channels keep their settings, kinds and quiet hours; the secret is
// replaced only when asked, and it is one of the sealed columns that the
// key checks and rekey see.
func TestAlertChannels(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	now := time.Unix(1_790_000_000, 0)
	c := model.AlertChannel{Name: "Админы", Kind: model.ChannelTelegram, Enabled: true, Settings: []byte(`{"chatId":"-100"}`),
		Events: []model.EventKind{model.EventServer, model.EventJob}, Quiet: model.QuietHours{From: "23:00", To: "08:00", Zone: "Europe/Moscow"}, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateAlertChannel(ctx, &c, func(id int64) ([]byte, error) { return sealedAs(1, "token"), nil }); err != nil {
		t.Fatal(err)
	}
	got, err := d.AlertChannelByID(ctx, c.ID)
	if err != nil || got.Name != "Админы" || got.Kind != model.ChannelTelegram || !got.Enabled || string(got.Settings) != `{"chatId":"-100"}` ||
		!slices.Equal(got.Events, c.Events) || got.Quiet != c.Quiet || !got.HasSecret || !got.CreatedAt.Equal(now) {
		t.Fatalf("read back %+v %v", got, err)
	}
	if !got.Wants(model.EventJob) || got.Wants(model.EventDisk) {
		t.Fatal("Wants")
	}

	// Without seal the secret stays; a webhook without one has none.
	got.Name, got.Enabled, got.Events = "Все", false, nil
	if err := d.UpdateAlertChannel(ctx, got, nil); err != nil {
		t.Fatal(err)
	}
	if s, _ := d.AlertChannelSecret(ctx, c.ID); !bytes.Equal(s, sealedAs(1, "token")) {
		t.Fatalf("secret %q", s)
	}
	w := model.AlertChannel{Name: "hook", Kind: model.ChannelWebhook, Enabled: true, CreatedAt: now, UpdatedAt: now}
	if err := d.CreateAlertChannel(ctx, &w, nil); err != nil || w.HasSecret {
		t.Fatal(w, err)
	}
	list, _ := d.ListAlertChannels(ctx)
	if len(list) != 2 || list[0].Name != "Все" || list[0].Enabled || len(list[0].Events) != 0 || !list[0].Wants(model.EventDisk) || list[1].HasSecret {
		t.Fatalf("list %+v", list)
	}

	// The secret is a sealed column: its version counts, rekey rewraps it
	// with its context.
	if vs, _ := d.SealedVersions(ctx); !slices.Equal(vs, []uint32{1}) {
		t.Fatalf("versions %v", vs)
	}
	var contexts []string
	if n, err := d.RewrapSealed(ctx, 2, func(_ []byte, cx string) ([]byte, error) {
		contexts = append(contexts, cx)
		return sealedAs(2, cx), nil
	}); err != nil || n != 1 || !slices.Equal(contexts, []string{model.AlertSecretContext(c.ID)}) {
		t.Fatalf("rewrap %d %v %v", n, err, contexts)
	}

	// A seal returning nil removes the secret.
	if err := d.UpdateAlertChannel(ctx, got, func(int64) ([]byte, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.AlertChannelByID(ctx, c.ID); got.HasSecret {
		t.Fatal("the secret stayed")
	}
	if err := d.DeleteAlertChannel(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AlertChannelByID(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := d.DeleteAlertChannel(ctx, c.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
	if err := d.UpdateAlertChannel(ctx, got, nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("update deleted: %v", err)
	}
}
