package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/store"
)

// A batch is stored with its servers in order; saving writes its state
// and every item; the unfinished ones are listed oldest first; a retry
// shows on the batch it retries; the scope filter keeps the batches all
// of whose servers (and the node they download through) are in it.
func TestBatches(t *testing.T) {
	ctx := context.Background()
	d, _ := openTemp(t)
	ids := addServers(t, d, "a", "b", "c")
	at := time.Unix(1_790_000_000, 0)
	b := model.Batch{Action: model.BatchMaintain, Params: json.RawMessage(`{"version":"v2.12.3"}`), Parallel: 3, State: model.BatchRunning,
		CreatedAt: at, UpdatedAt: at,
		Items: []model.BatchItem{{Idx: 0, ServerID: ids[1], State: model.ItemPending}, {Idx: 1, ServerID: ids[0], State: model.ItemPending}}}
	if err := d.CreateBatch(ctx, &b); err != nil || b.ID == 0 {
		t.Fatalf("%d %v", b.ID, err)
	}
	got, err := d.BatchByID(ctx, b.ID)
	if err != nil || got.Action != model.BatchMaintain || string(got.Params) != `{"version":"v2.12.3"}` || got.Parallel != 3 ||
		!slices.Equal(got.Servers(), []int64{ids[1], ids[0]}) || got.CreatedBy != 0 || !got.CreatedAt.Equal(at) {
		t.Fatalf("%+v %v", got, err)
	}

	j := model.Job{Kind: "maintain", ServerID: ids[1], State: model.JobQueued, CreatedAt: at}
	if err := d.CreateJob(ctx, &j, nil, nil); err != nil {
		t.Fatal(err)
	}
	got.Items[0].State, got.Items[0].JobID, got.Items[0].Canary, got.Items[0].At = model.ItemRunning, j.ID, true, at.Add(time.Second)
	got.Items[1].State, got.Items[1].Message = model.ItemSkipped, "stopped"
	got.State, got.Stop, got.UpdatedAt = model.BatchStopping, model.StopFailed, at.Add(time.Minute)
	if err := d.SaveBatch(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := d.BatchByID(ctx, b.ID)
	if again.State != model.BatchStopping || again.Stop != model.StopFailed || again.Items[0].JobID != j.ID || !again.Items[0].Canary ||
		again.Items[1].State != model.ItemSkipped || again.Items[1].Message != "stopped" || !again.Items[0].At.Equal(at.Add(time.Second)) {
		t.Fatalf("%+v", again)
	}
	if err := d.SaveBatch(ctx, model.Batch{ID: 9999}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing batch: %v", err)
	}

	via := model.Batch{Action: model.BatchGeo, Params: json.RawMessage(`{"source":"node","via":` + id64(ids[2]) + `}`), Parallel: 1, State: model.BatchCompleted,
		RetryOf: b.ID, CreatedAt: at, UpdatedAt: at, Items: []model.BatchItem{{ServerID: ids[0], State: model.ItemCompleted}}}
	if err := d.CreateBatch(ctx, &via); err != nil {
		t.Fatal(err)
	}
	if first, _ := d.BatchByID(ctx, b.ID); first.RetriedBy != via.ID {
		t.Fatalf("retried by %d", first.RetriedBy)
	}
	open, err := d.UnfinishedBatches(ctx)
	if err != nil || len(open) != 1 || open[0].ID != b.ID || len(open[0].Items) != 2 {
		t.Fatalf("unfinished %+v %v", open, err)
	}

	list := func(within []int64) []int64 {
		t.Helper()
		f := model.BatchFilter{}
		if within != nil {
			f.Within = &within
		}
		bs, err := d.ListBatches(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []int64
		for _, x := range bs {
			out = append(out, x.ID)
		}
		return out
	}
	if got := list(nil); !slices.Equal(got, []int64{via.ID, b.ID}) {
		t.Fatalf("all %v", got)
	}
	if got := list([]int64{ids[0], ids[1]}); !slices.Equal(got, []int64{b.ID}) {
		t.Fatalf("a and b: %v (the geo batch goes through c)", got)
	}
	if got := list([]int64{ids[0], ids[2]}); !slices.Equal(got, []int64{via.ID}) {
		t.Fatalf("a and c: %v", got)
	}
	if got := list([]int64{}); len(got) != 0 {
		t.Fatalf("none: %v", got)
	}
	if page, _ := d.ListBatches(ctx, model.BatchFilter{BeforeID: via.ID, Limit: 1}); len(page) != 1 || page[0].ID != b.ID {
		t.Fatalf("page %+v", page)
	}

	// A deleted server leaves the batch.
	if err := d.DeleteServer(ctx, ids[0]); err != nil {
		t.Fatal(err)
	}
	if left, _ := d.BatchByID(ctx, b.ID); !slices.Equal(left.Servers(), []int64{ids[1]}) {
		t.Fatalf("after delete %v", left.Servers())
	}
}

func id64(n int64) string { b, _ := json.Marshal(n); return string(b) }
