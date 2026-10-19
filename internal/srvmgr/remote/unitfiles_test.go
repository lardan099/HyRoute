package remote_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"testing"

	"github.com/lardan099/hyroute/internal/srvmgr/remote"
	"github.com/lardan099/hyroute/internal/srvmgr/remote/fake"
)

func hexSum(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}

// A unit's fingerprint is its file's SHA-256 without drop-ins, and covers
// every drop-in once there are some; it only reads (remote.ReadOnly).
func TestUnitSHA256(t *testing.T) {
	ctx := context.Background()
	const unit = "/etc/systemd/system/hysteria-server.service"
	const drop = "/etc/systemd/system/hysteria-server.service.d/override.conf"
	ex := fake.New()
	show := ex.On("systemctl", "show", "--no-pager", "-p", "LoadState,FragmentPath,DropInPaths", "--", "hysteria-server.service").
		Reply("LoadState=loaded\nFragmentPath="+unit+"\nDropInPaths=\n", 0)
	ex.On("sha256sum", "--", unit).Reply(hexSum("[Unit]\n")+"  "+unit+"\n", 0)
	ex.On("sha256sum", "--", drop).Reply(hexSum("[Service]\nUser=root\n")+"  "+drop+"\n", 0)
	ro := remote.ReadOnly(ex)

	sum, files, err := remote.UnitSHA256(ctx, ro, "hysteria-server.service", true)
	if err != nil || sum != hexSum("[Unit]\n") || !slices.Equal(files, []string{unit}) {
		t.Fatalf("without drop-ins: %s %q %v", sum, files, err)
	}
	show.Reply("LoadState=loaded\nFragmentPath="+unit+"\nDropInPaths="+drop+"\n", 0)
	sum, files, err = remote.UnitSHA256(ctx, ro, "hysteria-server.service", true)
	want := hexSum(hexSum("[Unit]\n") + "  " + unit + "\n" + hexSum("[Service]\nUser=root\n") + "  " + drop + "\n")
	if err != nil || sum != want || !slices.Equal(files, []string{unit, drop}) {
		t.Fatalf("with a drop-in: %s %q %v, want %s", sum, files, err, want)
	}
	show.Reply("LoadState=not-found\nFragmentPath=\nDropInPaths=\n", 0)
	if sum, files, err := remote.UnitSHA256(ctx, ro, "hysteria-server.service", true); err != nil || sum != "" || files != nil {
		t.Fatalf("no unit: %q %q %v", sum, files, err)
	}
	show.Reply("LoadState=loaded\nFragmentPath="+unit+"\nDropInPaths=relative.conf\n", 0)
	if _, _, err := remote.UnitSHA256(ctx, ro, "hysteria-server.service", true); err == nil {
		t.Fatal("a drop-in path that is not absolute accepted")
	}
	if _, _, err := remote.UnitSHA256(ctx, ro, "../x.service", true); err == nil {
		t.Fatal("bad unit name accepted")
	}
	if len(ex.Writes()) != 0 {
		t.Fatalf("writes: %+v", ex.Writes())
	}
}
