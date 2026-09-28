//go:build windows

package netwatch

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"github.com/lardan099/hyroute/internal/netmode"
)

// These talk to Windows: NLM, the neighbour table, the NetworkList
// signatures in the registry and WLAN (which Windows 11 may count as
// location use and list the test binary under recent location activity).
// They run only with HYROUTE_NETWATCH_SMOKE=1.
func smoke(t *testing.T) {
	if os.Getenv("HYROUTE_NETWATCH_SMOKE") != "1" {
		t.Skip("set HYROUTE_NETWATCH_SMOKE=1 to read this computer's networks")
	}
}

func TestSnapshotSmoke(t *testing.T) {
	smoke(t)
	w := New()
	start := time.Now()
	snap, err := w.Snapshot(false)
	if err != nil {
		t.Fatal(err)
	}
	// NLM is bounded by 6 s (hand-over and answer); the registry and the
	// neighbour table answer at once on a healthy system.
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("took %v", d)
	}
	if a := snap.Active; a != nil {
		switch a.Adapter {
		case netmode.WiFi, netmode.Ethernet, netmode.Mobile, netmode.Other:
		default:
			t.Fatalf("adapter %q", a.Adapter)
		}
		t.Logf("active: %s, %s, identified %v, gateway known %v, MAC known %v, err %q", a.Adapter, a.Category, a.Identified, a.GatewayIP != "", a.GatewayMAC != "", snap.Err)
	}
}

func TestWatchCancel(t *testing.T) {
	smoke(t)
	w := New()
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := w.Watch(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(50 * time.Millisecond)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	if _, err := w.Watch(ctx2); err != nil {
		t.Fatal(err)
	}
}

func TestSSIDNoPanic(t *testing.T) {
	smoke(t)
	w := New()
	snap, err := w.Snapshot(false)
	if err != nil || snap.Active == nil {
		t.Skip("no active network")
	}
	s, err := w.SSID(snap.Active.AdapterID)
	t.Logf("SSID known %v, err %v", s != "", err)
}

// TestIdentitySmoke checks what «Именно эта сеть» and every relaxing
// action rest on (ARCHITECTURE §16): the ID NLM gives a network is the
// GUID of its NetworkList profile, and a signature names it as ProfileGuid
// exactly when Windows identified the network. The tester says what the
// active network is: HYROUTE_NETWATCH_EXPECT=identified (a network Windows
// shows by its name: home Wi-Fi, office) or =unidentified («Неопознанная
// сеть», «Идентификация…»: e.g. a cable to a device without internet).
func TestIdentitySmoke(t *testing.T) {
	smoke(t)
	snap, err := New().Snapshot(false)
	if err != nil {
		t.Fatal(err)
	}
	a := snap.Active
	if a == nil {
		t.Skip("no active network")
	}
	if a.ID == "" {
		t.Fatalf("NLM gave the active network no ID (%q)", snap.Err)
	}
	profile := profileExists(t, a.ID)
	sigs := signaturesNaming(t, a.ID)
	t.Logf("active: %s, category %q, identified %v, profile %v, signatures naming its ID %d", a.Adapter, a.Category, a.Identified, profile, sigs)
	if !profile {
		t.Fatal("the NLM network ID is not a NetworkList profile GUID: identified() never matches, rework it")
	}
	switch os.Getenv("HYROUTE_NETWATCH_EXPECT") {
	case "identified":
		if !a.Identified {
			t.Fatal("an identified network has no signature with ProfileGuid = its NLM ID: GetNetworkId ≠ ProfileGuid, rework identified()")
		}
	case "unidentified":
		if a.Identified {
			t.Fatal("an unidentified network counts as identified: a disconnect rule could fire on a foreign network")
		}
	default:
		t.Log("set HYROUTE_NETWATCH_EXPECT=identified or =unidentified for a pass/fail answer")
	}
	for _, o := range snap.Others {
		if o.ID != "" {
			t.Logf("other connection: %s, category %q, profile %v, signatures naming its ID %d", o.Adapter, o.Category, profileExists(t, o.ID), signaturesNaming(t, o.ID))
		}
	}
}

const profilesKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\`

// profileExists: id is the GUID of a NetworkList profile (key names are
// case-insensitive).
func profileExists(t *testing.T, id string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profilesKey+id, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err == registry.ErrNotExist {
		return false
	}
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	k.Close()
	return true
}

// signaturesNaming counts the signatures (managed and unmanaged) whose
// ProfileGuid is id.
func signaturesNaming(t *testing.T, id string) int {
	n := 0
	for _, kind := range []string{"Unmanaged", "Managed"} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, signaturesKey+kind, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
		if err == registry.ErrNotExist {
			continue
		}
		if err != nil {
			t.Fatalf("signatures: %v", err)
		}
		names, err := k.ReadSubKeyNames(-1)
		if err != nil && err != io.EOF {
			k.Close()
			t.Fatalf("signatures: %v", err)
		}
		for _, name := range names {
			sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE|registry.WOW64_64KEY)
			if err != nil {
				continue
			}
			if v, _, err := sk.GetStringValue("ProfileGuid"); err == nil && strings.EqualFold(strings.TrimSpace(v), id) {
				n++
			}
			sk.Close()
		}
		k.Close()
	}
	return n
}
