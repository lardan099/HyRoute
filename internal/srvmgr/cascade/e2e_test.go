package cascade

// The end-to-end test of Phase 3 (P3-10): a cascade made over real SSH —
// the controller's sshexec against in-process SSH servers whose commands
// and files are the host simulator's — its check through the SSH tunnel
// to a SOCKS5 server on this machine's loopback, a direct rule on the
// entry by the apply job, and the link taken off again. Nothing runs on
// this machine but the loopback listeners.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/lardan099/hyroute/internal/hyconfig"
	"github.com/lardan099/hyroute/internal/socks5"
	"github.com/lardan099/hyroute/internal/srvmgr/apply"
	"github.com/lardan099/hyroute/internal/srvmgr/jobs"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/redact"
	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshexec"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// shellSplit undoes remote.CommandLine: the words of a line without the
// sudo and C-locale prefixes.
func shellSplit(line string) []string {
	line = strings.TrimPrefix(line, "sudo -n -- ")
	var words []string
	var w strings.Builder
	in, has := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case in:
			if c == '\'' {
				in = false
			} else {
				w.WriteByte(c)
			}
		case c == '\'':
			in, has = true, true
		case c == '\\' && i+1 < len(line):
			i++
			w.WriteByte(line[i])
			has = true
		case c == ' ':
			if has {
				words = append(words, w.String())
				w.Reset()
				has = false
			}
		default:
			w.WriteByte(c)
			has = true
		}
	}
	if has {
		words = append(words, w.String())
	}
	if len(words) >= 3 && words[0] == "env" && words[1] == "LC_ALL=C" && words[2] == "LANG=C" {
		words = words[3:]
	}
	return words
}

var e2eTmp atomic.Int64

// exec runs an SSH exec request on the simulator, with what sshexec's own
// file writes need besides (mktemp -d, install, rm -rf).
func (h *host) exec(ctx context.Context, line string, _ io.Reader, stdout, stderr io.Writer) int {
	a := shellSplit(line)
	if len(a) == 0 {
		return 127
	}
	h.mu.Lock()
	switch {
	case a[0] == "mktemp":
		h.mu.Unlock()
		fmt.Fprintf(stdout, "/tmp/hyroute.e2e%07d\n", e2eTmp.Add(1))
		return 0
	case a[0] == "rm" && len(a) > 2 && a[1] == "-rf":
		dir := a[len(a)-1]
		for p := range h.files {
			if strings.HasPrefix(p, dir+"/") {
				delete(h.files, p)
			}
		}
		h.mu.Unlock()
		return 0
	case a[0] == "install" && len(a) > 3 && a[1] == "-m":
		src, dst := a[len(a)-2], a[len(a)-1]
		b, found := h.files[src]
		if !found {
			h.mu.Unlock()
			io.WriteString(stderr, "install: cannot stat "+src)
			return 1
		}
		owner, group := "root", "root"
		for i := 2; i+1 < len(a); i++ {
			switch a[i] {
			case "-o":
				owner = a[i+1]
			case "-g":
				group = a[i+1]
			}
		}
		h.files[dst] = append([]byte(nil), b...)
		h.modes[dst] = strings.TrimPrefix(a[2], "0") + " " + owner + " " + group
		h.mu.Unlock()
		return 0
	}
	h.mu.Unlock()
	res, err := h.Run(ctx, remote.Cmd{Args: a})
	if err != nil {
		io.WriteString(stderr, err.Error())
		return 255
	}
	stdout.Write(res.Stdout)
	stderr.Write(res.Stderr)
	return res.ExitCode
}

// hostFS is the simulator's files over SFTP.
type hostFS struct{ h *host }

func (f hostFS) handlers() sftp.Handlers {
	return sftp.Handlers{FileGet: f, FilePut: f, FileCmd: f, FileList: f}
}

func (f hostFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	b, found := f.h.files[r.Filepath]
	if !found {
		return nil, os.ErrNotExist
	}
	return bytes.NewReader(append([]byte(nil), b...)), nil
}

func (f hostFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	f.h.files[r.Filepath] = []byte{}
	return hostFile{f.h, r.Filepath}, nil
}

type hostFile struct {
	h *host
	p string
}

func (w hostFile) WriteAt(p []byte, off int64) (int, error) {
	w.h.mu.Lock()
	defer w.h.mu.Unlock()
	b := w.h.files[w.p]
	if n := int(off) + len(p); n > len(b) {
		nb := make([]byte, n)
		copy(nb, b)
		b = nb
	}
	copy(b[off:], p)
	w.h.files[w.p] = b
	return len(p), nil
}

func (f hostFS) Filecmd(r *sftp.Request) error {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	switch r.Method {
	case "Setstat", "Mkdir":
		return nil
	case "Remove":
		delete(f.h.files, r.Filepath)
		return nil
	case "Rename":
		f.h.files[r.Target] = f.h.files[r.Filepath]
		delete(f.h.files, r.Filepath)
		return nil
	}
	return os.ErrPermission
}

type fileInfo struct {
	name string
	size int64
}

func (i fileInfo) Name() string       { return i.name }
func (i fileInfo) Size() int64        { return i.size }
func (i fileInfo) Mode() fs.FileMode  { return 0o644 }
func (i fileInfo) ModTime() time.Time { return time.Time{} }
func (i fileInfo) IsDir() bool        { return false }
func (i fileInfo) Sys() any           { return nil }

type lister []fs.FileInfo

func (l lister) ListAt(out []fs.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[off:])
	if n < len(out) {
		return n, io.EOF
	}
	return n, nil
}

func (f hostFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	b, found := f.h.files[r.Filepath]
	if !found || (r.Method != "Stat" && r.Method != "Lstat") {
		return nil, os.ErrNotExist
	}
	return lister{fileInfo{path.Base(r.Filepath), int64(len(b))}}, nil
}

// serve puts a simulated host behind an in-process SSH server.
func serve(t *testing.T, h *host) *sshtest.Server {
	srv := sshtest.Start(t, "root", "fake-e2e-ssh-pass")
	srv.SetExec(h.exec)
	srv.SetHandlers(hostFS{h}.handlers())
	return srv
}

// sshHosts connects to the servers by SSH, trusting each one's key.
type sshHosts map[int64]*sshtest.Server

func (s sshHosts) Connect(ctx context.Context, id int64) (remote.Executor, error) {
	srv, found := s[id]
	if !found {
		return nil, errors.New("no such server")
	}
	return sshexec.Dial(ctx, sshexec.Target{Host: srv.Host, Port: srv.Port, User: srv.User}, sshexec.Auth{Password: srv.Password}, sshexec.Options{
		Timeout: 5 * time.Second,
		HostKey: func(k ssh.PublicKey) error {
			if !bytes.Equal(k.Marshal(), srv.HostKey().Marshal()) {
				return errors.New("unknown host key")
			}
			return nil
		},
	})
}

func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, exitPW)
	w.stop() // the simulators' own controller: this one goes by SSH
	conn := sshHosts{w.in: serve(t, w.entry), w.out: serve(t, w.exit)}
	eng := jobs.New(w.db, w.keys, redact.New(), conn, nil)
	eng.Poll = 10 * time.Millisecond
	l := New(Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 2 * time.Second, Poll: 10 * time.Millisecond})
	eng.Register(l.Kind())
	eng.Register(l.UnlinkKind())
	app := apply.New(apply.Deps{Store: w.db, Keys: w.keys, Jobs: eng, VerifyTimeout: 2 * time.Second, Poll: 10 * time.Millisecond})
	eng.Register(app.Kind())
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { eng.Run(runCtx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	w.linker = l

	// The link client stands on this machine's loopback, with the link's
	// login; the check target too.
	sec := Secrets{SOCKSUser: "link-e2e", SOCKSPassword: "fake-e2e-socks-pass"}
	sealed, err := SealSecrets(w.keys, w.chain, 0, sec)
	if err != nil {
		t.Fatal(err)
	}
	w.db.SetLinkSecrets(ctx, w.chain, 0, sealed, time.Now())
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { target.Close() })
	go func() {
		for {
			c, err := target.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	client := &socks5.Server{Username: sec.SOCKSUser, Password: sec.SOCKSPassword}
	if err := client.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	_, port, _ := net.SplitHostPort(client.Addr())
	var localPort int
	fmt.Sscan(port, &localPort)
	link := w.link()
	link.Params = Params{LocalPort: localPort, CheckTarget: target.Addr().String()}.Raw()
	if err := w.db.UpdateLink(ctx, link); err != nil {
		t.Fatal(err)
	}

	// The link.
	j, log := w.wait(w.submit())
	if j.State != model.JobCompleted {
		t.Fatalf("link: %s %s %s\n%s", j.State, j.ErrorMessage, j.ErrorDetails, log)
	}
	if !strings.Contains(log, "мс") && !strings.Contains(log, "ms") {
		t.Logf("log:\n%s", log)
	}
	entryCfg, _ := w.entry.file(cfgPath)
	c, err := hyconfig.ParseServer([]byte(entryCfg))
	if err != nil || len(c.Outbounds) == 0 || c.Outbounds[0].Name != OutboundName {
		t.Fatalf("entry outbounds: %v\n%s", err, entryCfg)
	}
	if _, found := w.entry.file(linkCfg(w)); !found || w.entry.unit(UnitName(w.chain, 0)) != "active" || w.link().State != model.LinkActive {
		t.Fatalf("link client: %s %s", w.entry.unit(UnitName(w.chain, 0)), w.link().State)
	}

	// Checked now, over SSH, through the tunnel.
	entry, _ := w.db.ServerByID(ctx, w.in)
	ex, err := conn.Connect(ctx, w.in)
	if err != nil {
		t.Fatal(err)
	}
	k := &Checker{Store: w.db, Keys: w.keys}
	down, err := k.CheckLinks(ctx, entry, ex)
	ex.Close()
	if err != nil || down != "" {
		t.Fatalf("check: %q %v", down, err)
	}
	checks, _ := w.db.LinkChecks(ctx, w.chain, 0, time.Time{}, 1)
	if len(checks) == 0 || checks[0].Status != model.StateHealthy || checks[0].TCPMillis == 0 && checks[0].HandshakeMillis == 0 {
		t.Fatalf("checks %+v", checks)
	}

	// A direct rule on the entry, by the apply job.
	cur, _ := w.db.CurrentConfig(ctx, w.in)
	ed := &apply.Editor{Store: w.db, Keys: w.keys}
	ch, cand, base, err := ed.Candidate(ctx, w.in, cur.Revision, func(c *hyconfig.Server) error {
		c.ACL.Inline = append(c.ACL.Inline, "direct(suffix:ru)")
		return nil
	})
	if err != nil || !ch.OK {
		t.Fatalf("%v %+v", err, ch.Problems)
	}
	aj, err := app.Queue(ctx, w.in, base, ch, cand, apply.ChangeRouting, 0)
	if err != nil {
		t.Fatal(err)
	}
	if aj, log = w.wait(aj); aj.State != model.JobCompleted {
		t.Fatalf("apply: %s %s %s\n%s", aj.State, aj.ErrorMessage, aj.ErrorDetails, log)
	}
	if s, _ := w.entry.file(cfgPath); !strings.Contains(s, "direct(suffix:ru)") || !strings.Contains(s, OutboundName) {
		t.Fatalf("entry config:\n%s", s)
	}

	// The link off: its files and outbound go, the rule stays.
	uj, err := l.Unlink(ctx, w.chain, 0, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	if uj, log = w.wait(uj); uj.State != model.JobCompleted {
		t.Fatalf("unlink: %s %s %s\n%s", uj.State, uj.ErrorMessage, uj.ErrorDetails, log)
	}
	s, _ := w.entry.file(cfgPath)
	if strings.Contains(s, OutboundName) || !strings.Contains(s, "direct(suffix:ru)") {
		t.Fatalf("entry config after unlink:\n%s", s)
	}
	if _, found := w.entry.file(linkCfg(w)); found || w.link().State != model.LinkNew {
		t.Fatalf("link left: %s", w.link().State)
	}
	if strings.Contains(cmdLines(w.entry), "fake-e2e-socks-pass") || strings.Contains(cmdLines(w.exit), "fake-exit-pass") {
		t.Fatal("a secret in a command line")
	}

	// It all went by SSH: on the entry uploads by SFTP (mktemp, then
	// install of the upload), restarts and the ping; the password exit is
	// only read.
	in := strings.Join(conn[w.in].Lines(), "\n")
	if !strings.Contains(in, "mktemp -d") || !strings.Contains(in, "/upload") || !strings.Contains(in, "systemctl restart") || !strings.Contains(in, " ping ") {
		t.Fatalf("entry by SSH:\n%s", in)
	}
	if out := strings.Join(conn[w.out].Lines(), "\n"); !strings.Contains(out, "sha256sum -- "+cfgPath) || strings.Contains(out, "install") {
		t.Fatalf("exit by SSH:\n%s", out)
	}
}

func cmdLines(h *host) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.cmds, "\n")
}
