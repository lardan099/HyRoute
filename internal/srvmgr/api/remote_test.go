package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/auth"
	"github.com/lardan099/hyroute/internal/srvmgr/model"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// probeExec answers the probe of a root login.
func probeExec(_ context.Context, line string, _ io.Reader, out, _ io.Writer) int {
	switch strings.TrimPrefix(strings.TrimPrefix(line, "sudo -n -- "), "env LC_ALL=C LANG=C ") {
	case "id -un":
		fmt.Fprintln(out, "root")
	case "id -u":
		fmt.Fprintln(out, "0")
	case "uname -n":
		fmt.Fprintln(out, "vps")
	case "uname -sr":
		fmt.Fprintln(out, "Linux 6.1.0")
	case "uname -m":
		fmt.Fprintln(out, "aarch64")
	default:
		return 127
	}
	return 0
}

func TestCheckAndTrustFlow(t *testing.T) {
	e := newEnv(t)
	owner := e.setupOwner()
	srv := sshtest.Start(t, "root", fakeSSHPass)
	srv.SetExec(probeExec)
	rec := owner.do("POST", "/api/v1/servers", map[string]any{"name": "S", "host": srv.Host, "sshPort": srv.Port, "authType": "password", "password": fakeSSHPass}, nil)
	var created serverJSON
	json.Unmarshal(rec.Body.Bytes(), &created)
	id := strconv.FormatInt(created.ID, 10)
	if created.HostKey != nil {
		t.Fatal("new server has a trusted key")
	}

	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	code(t, rec, http.StatusConflict, "host_key_unknown")
	var body struct {
		Error struct {
			Data map[string]string
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &body)
	fp := body.Error.Data["fingerprint"]
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("no fingerprint to confirm: %s", rec.Body)
	}

	code(t, owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": "SHA256:nope"}, nil), http.StatusConflict, "fingerprint_mismatch")
	rec = owner.do("POST", "/api/v1/servers/"+id+"/host-key", map[string]any{"fingerprint": fp}, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), fp) {
		t.Fatalf("trust: %d %s", rec.Code, rec.Body)
	}
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"arch":"aarch64"`) || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("check: %d %s", rec.Code, rec.Body)
	}
	rec = owner.do("GET", "/api/v1/servers/"+id, nil, nil)
	if !strings.Contains(rec.Body.String(), `"fingerprint":"`+fp) {
		t.Fatalf("server without its key: %s", rec.Body)
	}

	// A changed key is reported with both fingerprints.
	srv.SetHostKey(sshtest.NewSigner(t))
	rec = owner.do("POST", "/api/v1/servers/"+id+"/check", nil, nil)
	code(t, rec, http.StatusConflict, "host_key_changed")
	if !strings.Contains(rec.Body.String(), `"oldFingerprint":"`+fp) {
		t.Fatalf("%s", rec.Body)
	}
}

// Requests open a bounded number of SSH connections to one server, and a
// user a bounded number of live journals of it.
func TestSSHSlots(t *testing.T) {
	s := &server{}
	as := func(user int64) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		return r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{User: model.User{ID: user}}))
	}
	take := func(user, srv int64, follow bool) func() {
		t.Helper()
		release, ok := s.sshSlot(httptest.NewRecorder(), as(user), srv, follow)
		if !ok {
			t.Fatalf("user %d, server %d, follow %v: refused", user, srv, follow)
		}
		return release
	}
	refused := func(user, srv int64, follow bool, code string) {
		t.Helper()
		rec := httptest.NewRecorder()
		if _, ok := s.sshSlot(rec, as(user), srv, follow); ok || rec.Code != http.StatusTooManyRequests || decodeError(t, rec).Code != code {
			t.Fatalf("user %d, server %d, follow %v: %v %d %s", user, srv, follow, ok, rec.Code, rec.Body)
		}
	}
	var held []func()
	for range maxFollows {
		held = append(held, take(1, 7, true))
	}
	refused(1, 7, true, "too_many_journals")
	take(1, 8, true)() // another server
	held = append(held, take(2, 7, true))
	for len(held) < maxServerConns {
		held = append(held, take(3, 7, false))
	}
	refused(3, 7, false, "too_many_connections")
	refused(2, 7, true, "too_many_connections")
	take(3, 8, false)()
	held[0]() // a journal closed
	take(1, 7, true)()
	for _, release := range held[1:] {
		release()
	}
	if len(s.ssh.conns) != 0 || len(s.ssh.follows) != 0 {
		t.Fatalf("slots left: %v %v", s.ssh.conns, s.ssh.follows)
	}
}
