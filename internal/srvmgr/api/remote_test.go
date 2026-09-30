package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote/sshtest"
)

// probeExec answers the probe of a root login.
func probeExec(_ context.Context, line string, _ io.Reader, out, _ io.Writer) int {
	switch strings.TrimPrefix(strings.TrimPrefix(line, "sudo -n -- "), "env LC_ALL=C LANG=C ") {
	case "id -un":
		fmt.Fprintln(out, "root")
	case "id -u":
		fmt.Fprintln(out, "0")
	case "hostname":
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
