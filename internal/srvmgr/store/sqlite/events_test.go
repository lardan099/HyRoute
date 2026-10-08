package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// One open event per key: a repeat glues into it, a closed one leaves
// room for a new one; pruning drops closed events only.
func TestEvents(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	at := time.Unix(1_790_000_000, 0)
	e := model.Event{Kind: model.EventDisk, Key: "disk:1", Severity: model.SeverityWarning, Subject: model.SubjectServer, SubjectID: 1, Text: "full", OpenedAt: at}
	first, opened, err := d.RaiseEvent(ctx, e)
	if err != nil || !opened || first.Count != 1 || !first.Open() || !first.OpenedAt.Equal(at) {
		t.Fatalf("first %+v %v %v", first, opened, err)
	}
	e.Text, e.Severity, e.OpenedAt = "fuller", model.SeverityCritical, at.Add(time.Minute)
	again, opened, err := d.RaiseEvent(ctx, e)
	if err != nil || opened || again.ID != first.ID || again.Count != 2 || again.Text != "fuller" || again.Severity != model.SeverityCritical ||
		!again.OpenedAt.Equal(at) || !again.LastAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("again %+v %v %v", again, opened, err)
	}
	if _, closed, err := d.CloseEvent(ctx, "other", at, "x"); err != nil || closed {
		t.Fatalf("closing nothing: %v %v", closed, err)
	}
	done, closed, err := d.CloseEvent(ctx, "disk:1", at.Add(2*time.Minute), "fine")
	if err != nil || !closed || done.Open() || done.CloseText != "fine" {
		t.Fatalf("closed %+v %v %v", done, closed, err)
	}
	e.OpenedAt = at.Add(3 * time.Minute)
	if third, opened, err := d.RaiseEvent(ctx, e); err != nil || !opened || third.ID == first.ID {
		t.Fatalf("third %+v %v %v", third, opened, err)
	}
	other := model.Event{Kind: model.EventNetwork, Key: "network", Severity: model.SeverityCritical, Subject: model.SubjectController, Text: "down", OpenedAt: at}
	d.RaiseEvent(ctx, other)

	all, err := d.ListEvents(ctx, model.EventFilter{})
	if err != nil || len(all) != 3 || all[0].Key != "network" {
		t.Fatalf("all %+v %v", all, err)
	}
	open, _ := d.ListEvents(ctx, model.EventFilter{OpenOnly: true})
	if len(open) != 2 {
		t.Fatalf("open %+v", open)
	}
	page, _ := d.ListEvents(ctx, model.EventFilter{BeforeID: all[0].ID, Limit: 1})
	if len(page) != 1 || page[0].ID != all[1].ID {
		t.Fatalf("page %+v", page)
	}
	if err := d.PruneEvents(ctx, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if left, _ := d.ListEvents(ctx, model.EventFilter{}); len(left) != 2 || !left[0].Open() || !left[1].Open() {
		t.Fatalf("after pruning %+v", left)
	}
}
