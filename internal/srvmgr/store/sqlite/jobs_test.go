package sqlite

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/model"
)

// Within keeps the jobs whose every server is in the set (P4-04): the
// others of a cascade link and the node a job downloads through count;
// jobs of no server are left out.
func TestJobsWithin(t *testing.T) {
	d, _ := openTemp(t)
	ctx := context.Background()
	ids := addServers(t, d, "a", "b")
	a, b := ids[0], ids[1]
	add := func(server int64, others []int64, params any) int64 {
		t.Helper()
		raw, _ := json.Marshal(params)
		j := model.Job{Kind: "k", ServerID: server, Servers: others, State: model.JobFailed, Params: raw, CreatedAt: time.Now()}
		if err := d.CreateJob(ctx, &j, []model.JobStep{{Idx: 0, Name: "s"}}, nil); err != nil {
			t.Fatal(err)
		}
		l := model.JobLog{JobID: j.ID, Time: time.Now(), Level: "info", Message: "line"}
		if err := d.AppendJobLog(ctx, &l); err != nil {
			t.Fatal(err)
		}
		return j.ID
	}
	onA := add(a, nil, map[string]any{})
	link := add(a, []int64{b}, map[string]any{})
	viaB := add(a, nil, map[string]any{"via": b})
	onB := add(b, nil, map[string]any{"via": 0})
	none := add(0, nil, map[string]any{})
	for _, c := range []struct {
		within *[]int64
		want   []int64
	}{
		{nil, []int64{none, onB, viaB, link, onA}},
		{&[]int64{a}, []int64{onA}},
		{&[]int64{b}, []int64{onB}},
		{&[]int64{a, b}, []int64{onB, viaB, link, onA}},
		{&[]int64{}, nil},
	} {
		js, err := d.ListJobs(ctx, model.JobFilter{Within: c.within})
		if err != nil {
			t.Fatal(err)
		}
		var got []int64
		for _, j := range js {
			got = append(got, j.ID)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("jobs within %v: %v, want %v", c.within, got, c.want)
		}
		hits, err := d.SearchJobLogs(ctx, model.JobLogFilter{Within: c.within})
		if err != nil {
			t.Fatal(err)
		}
		got = nil
		for _, h := range hits {
			got = append(got, h.JobID)
		}
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("logs within %v: %v, want %v", c.within, got, want)
		}
	}
	// With a server too.
	js, _ := d.ListJobs(ctx, model.JobFilter{ServerID: b, Within: &[]int64{b}})
	if len(js) != 1 || js[0].ID != onB {
		t.Errorf("%+v", js)
	}
}
