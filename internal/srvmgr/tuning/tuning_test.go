package tuning

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/secrets"
	"github.com/lardan099/hyroute/internal/srvmgr/store/sqlite"
)

// kernel is a server's kernel parameters, modules and files.
type kernel struct {
	mu      sync.Mutex
	params  map[string]string
	modules map[string]bool
	files   map[string][]byte
	// reject: values the kernel refuses to take (sysctl -p sets the others).
	reject map[string]bool
	cmds   []string
	writes int
}

func newKernel() *kernel {
	return &kernel{
		params: map[string]string{
			Rmem: "212992", Wmem: "212992", Qdisc: "fq_codel", TCPCC: "cubic",
			avail: "reno cubic",
		},
		modules: map[string]bool{"tcp_bbr": true, "sch_fq": true},
		files:   map[string][]byte{},
		reject:  map[string]bool{},
	}
}

func ok(out string) remote.Result { return remote.Result{Stdout: []byte(out)} }

func (k *kernel) set(key, value string) bool {
	if k.reject[key] {
		return false
	}
	if key == TCPCC && value == "bbr" {
		if !k.modules["tcp_bbr"] {
			return false
		}
		if !strings.Contains(k.params[avail], "bbr") {
			k.params[avail] += " bbr" // the module loads
		}
	}
	k.params[key] = value
	return true
}

func (k *kernel) Run(_ context.Context, cmd remote.Cmd) (remote.Result, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	a := cmd.Args
	line := strings.Join(a, " ")
	k.cmds = append(k.cmds, line)
	last := a[len(a)-1]
	switch {
	case line == "id -un":
		return ok("root\n"), nil
	case line == "id -u":
		return ok("0\n"), nil
	case a[0] == "hostname":
		return ok("vps\n"), nil
	case line == "uname -sr":
		return ok("Linux 6.1.0\n"), nil
	case line == "uname -m":
		return ok("x86_64\n"), nil
	case a[0] == "sysctl" && a[1] == "-e":
		var out string
		for _, key := range a[2:] {
			if v, found := k.params[key]; found {
				out += key + " = " + strings.ReplaceAll(v, " ", "\t") + "\n"
			}
		}
		return ok(out), nil
	case a[0] == "sysctl" && a[2] == "-w":
		key, value, _ := strings.Cut(last, "=")
		k.set(key, value)
		return ok(""), nil
	case a[0] == "sysctl" && a[2] == "-p":
		failed := false
		for _, l := range strings.Split(string(k.files[last]), "\n") {
			if key, value, found := strings.Cut(l, "="); found && !strings.HasPrefix(l, "#") {
				if !k.set(strings.TrimSpace(key), strings.TrimSpace(value)) {
					failed = true
				}
			}
		}
		if failed {
			return remote.Result{ExitCode: 255, Stderr: []byte("sysctl: setting key: Invalid argument")}, nil
		}
		return ok(""), nil
	case a[0] == "modinfo":
		if k.modules[last] {
			return ok(last + "\n"), nil
		}
		return remote.Result{ExitCode: 1}, nil
	case a[0] == "sha256sum":
		b, found := k.files[last]
		if !found {
			return remote.Result{ExitCode: 1, Stderr: []byte("No such file")}, nil
		}
		s := sha256.Sum256(b)
		return ok(hex.EncodeToString(s[:]) + "  " + last + "\n"), nil
	case a[0] == "cp":
		k.files[last] = append([]byte(nil), k.files[a[len(a)-2]]...)
		k.writes++
		return ok(""), nil
	case a[0] == "mv":
		k.files[last] = k.files[a[len(a)-2]]
		delete(k.files, a[len(a)-2])
		k.writes++
		return ok(""), nil
	case a[0] == "rm":
		if _, found := k.files[last]; found {
			k.writes++
		}
		delete(k.files, last)
		return ok(""), nil
	}
	return remote.Result{ExitCode: 127, Stderr: []byte("kernel: unknown command " + line)}, nil
}

func (k *kernel) Stream(context.Context, remote.Cmd, func(string)) error { return errors.New("no") }

func (k *kernel) ReadFile(_ context.Context, p string, _ bool) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	b, found := k.files[p]
	if !found {
		return nil, fs.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (k *kernel) WriteFile(_ context.Context, p string, data []byte, _ remote.FileSpec) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.files[p] = append([]byte(nil), data...)
	k.writes++
	return nil
}

func (k *kernel) Close() error { return nil }

func (k *kernel) ran(prefix string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, c := range k.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (k *kernel) reset() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.cmds, k.writes = nil, 0
}

type conn struct{ k *kernel }

func (c conn) Connect(context.Context, int64) (remote.Executor, error) { return c.k, nil }

type harness struct {
	t      *testing.T
	db     *sqlite.DB
	eng    *jobs.Engine
	server int64
}

func newHarness(t *testing.T, k *kernel) *harness {
	t.Helper()
	ctx := context.Background()
	db, err := sqlite.Open(ctx, filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	keys, _ := secrets.NewKeyring(map[uint32][]byte{1: bytes.Repeat([]byte{6}, 32)})
	srv := model.Server{Name: "s", Host: "192.0.2.90", SSHPort: 22, SSHUser: "root", AuthType: model.AuthPassword, Role: model.RoleStandalone, State: model.StateHealthy}
	db.CreateServer(ctx, &srv, nil)
	eng := jobs.New(db, keys, redact.New(), conn{k}, nil)
	eng.Poll = 10 * time.Millisecond
	eng.Register(Kind())
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { eng.Run(cctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return &harness{t: t, db: db, eng: eng, server: srv.ID}
}

func (h *harness) run(keys ...string) (model.Job, string) {
	h.t.Helper()
	ctx := context.Background()
	j, err := h.eng.Submit(ctx, JobKind, h.server, Params{Keys: keys}, nil, 0)
	if err != nil {
		h.t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, _ = h.db.JobByID(ctx, j.ID)
		if j.State.Terminal() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	logs, _ := h.db.JobLogs(ctx, j.ID, 0, 1000)
	var b strings.Builder
	for _, l := range logs {
		fmt.Fprintln(&b, l.Message)
	}
	return j, b.String()
}

func TestRead(t *testing.T) {
	k := newKernel()
	st, err := Read(context.Background(), k, "Linux 6.1.0")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := st.Setting(Rmem)
	cc, _ := st.Setting(TCPCC)
	if !st.BBR || r.Want != "16777216" || r.Done || !r.Supported || cc.Want != "bbr" || cc.Current != "cubic" || !cc.Supported || st.File != "" {
		t.Fatalf("%+v", st)
	}
	// A larger limit is kept, not lowered.
	k.params[Wmem] = "67108864"
	st, _ = Read(context.Background(), k, "")
	if w, _ := st.Setting(Wmem); w.Want != "67108864" || !w.Done {
		t.Fatalf("%+v", w)
	}
}

// What the kernel cannot do is not offered, and a job asking for it is
// refused before anything changes.
func TestUnsupported(t *testing.T) {
	k := newKernel()
	delete(k.modules, "tcp_bbr")
	delete(k.modules, "sch_fq")
	st, _ := Read(context.Background(), k, "")
	cc, _ := st.Setting(TCPCC)
	q, _ := st.Setting(Qdisc)
	if st.BBR || cc.Supported || q.Supported || !strings.Contains(cc.Why, "tcp_bbr") {
		t.Fatalf("%+v", st)
	}
	if _, err := Plan(st, []string{Rmem, TCPCC}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("plan: %v", err)
	}
	if _, err := Plan(st, []string{"kernel.panic"}); err == nil {
		t.Fatal("another key planned")
	}
	h := newHarness(t, k)
	j, _ := h.run(Rmem, TCPCC)
	if j.State != model.JobFailed || !strings.Contains(j.ErrorMessage, "BBR") || k.writes != 0 {
		t.Fatalf("%s: %s, writes %d", j.State, j.ErrorMessage, k.writes)
	}
}

func TestApply(t *testing.T) {
	k := newKernel()
	h := newHarness(t, k)
	j, log := h.run(Rmem, Wmem, Qdisc, TCPCC)
	if j.State != model.JobCompleted {
		t.Fatalf("%s: %s\n%s", j.State, j.ErrorMessage, log)
	}
	f := string(k.files[FilePath])
	for _, want := range []string{"net.core.rmem_max = 16777216", "net.core.wmem_max = 16777216", "net.core.default_qdisc = fq", "net.ipv4.tcp_congestion_control = bbr"} {
		if !strings.Contains(f, want) {
			t.Fatalf("file:\n%s", f)
		}
	}
	if k.params[TCPCC] != "bbr" || k.params[Rmem] != "16777216" || k.params[Qdisc] != "fq" {
		t.Fatalf("%v", k.params)
	}
	if !strings.Contains(log, "net.ipv4.tcp_congestion_control: cubic → bbr") {
		t.Fatal(log)
	}

	// Again: nothing changes on the server.
	k.reset()
	j, log = h.run(Rmem, Wmem, Qdisc, TCPCC)
	if j.State != model.JobCompleted || k.writes != 0 || k.ran("sysctl -q -p") || k.ran("sysctl -q -w") {
		t.Fatalf("%s writes %d %q\n%s", j.State, k.writes, k.cmds, log)
	}
}

// Values the kernel does not take: the previous file and values come
// back.
func TestRollback(t *testing.T) {
	k := newKernel()
	prev := "# the admin's\nnet.core.rmem_max = 4194304\n"
	k.files[FilePath] = []byte(prev)
	k.reject[Qdisc] = true
	h := newHarness(t, k)
	j, log := h.run(Rmem, Qdisc, TCPCC)
	if j.State != model.JobFailed || j.CurrentStep != "load" {
		t.Fatalf("%s at %s: %s\n%s", j.State, j.CurrentStep, j.ErrorMessage, log)
	}
	if string(k.files[FilePath]) != prev {
		t.Fatalf("file not restored:\n%s", k.files[FilePath])
	}
	if _, left := k.files[FilePath+Backup]; left {
		t.Fatal("backup left")
	}
	if k.params[Rmem] != "212992" || k.params[TCPCC] != "cubic" {
		t.Fatalf("values not restored: %v", k.params)
	}
	if !strings.Contains(log, "Прежний "+FilePath+" возвращён") || !strings.Contains(log, "Прежние значения возвращены") {
		t.Fatal(log)
	}

	// A server without the file: the rollback removes HyRoute's.
	k2 := newKernel()
	k2.reject[TCPCC] = true
	h2 := newHarness(t, k2)
	if j, _ = h2.run(Rmem, TCPCC); j.State != model.JobFailed {
		t.Fatalf("%s", j.State)
	}
	if _, left := k2.files[FilePath]; left || k2.params[Rmem] != "212992" {
		t.Fatalf("file %q, %v", k2.files[FilePath], k2.params)
	}
}
