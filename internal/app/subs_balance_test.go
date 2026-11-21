package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/lardan099/hyroute/internal/rules"
	"github.com/lardan099/hyroute/internal/vless"
)

const balanceJSON = `[
  {
    "remarks": "Автовыбор",
    "inbounds": [{"listen":"0.0.0.0","port":32100,"protocol":"socks"}],
    "log":{"access":"ignored.log"},
    "outbounds": [
      {"tag":"node-a","protocol":"vless","settings":{"address":"a.example","port":443,"id":"test-balance-secret-a"},
       "streamSettings":{"network":"tcp","security":"tls","finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"20-40","interval":"5-10"}}]}}},
      {"tag":"node-b","protocol":"vless","settings":{"address":"b.example","port":443,"id":"test-balance-secret-b"},
       "streamSettings":{"network":"tcp","security":"tls"}},
      {"tag":"direct","protocol":"freedom"}
    ],
    "routing":{
      "rules":[{"type":"field","network":"tcp,udp","balancerTag":"auto"}],
      "balancers":[{"tag":"auto","selector":["node-"],"strategy":{"type":"leastLoad","settings":{"maxRTT":"6s","expected":1,"tolerance":0.2}}}]
    }
  },
  {
    "remarks":"Сервер",
    "outbounds":[{"tag":"direct-node","protocol":"vless","settings":{"address":"a.example","port":443,"id":"test-balance-secret-a"},"streamSettings":{"security":"tls"}}]
  }
]`

func TestSubscriptionReplacesPlaceholderWithSelectableXrayBalance(t *testing.T) {
	ctl, sessions := newCtl(t)
	ctl.Device = func(string) DeviceInfo { return DeviceInfo{HWID: "test-device"} }
	const plain = "vless://placeholder-id@placeholder.example:1234?security=tls#Автовыбор\nvless://test-balance-secret-a@a.example:443?security=tls#Сервер"
	var available atomic.Bool
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Profile-Web-Page-Url", "https://example.org/subscription")
		if !strings.HasPrefix(req.UserAgent(), "Happ/") {
			fmt.Fprint(w, plain)
			return
		}
		if req.Header.Get("X-Hwid") != "test-device" {
			t.Error("alternate request lost the device ID")
		}
		if !available.Load() {
			http.Error(w, "format unavailable", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, balanceJSON)
	}))
	defer s.Close()
	orig := directTransport
	directTransport = s.Client().Transport.(*http.Transport).Clone()
	defer func() {
		directTransport.CloseIdleConnections()
		directTransport = orig
	}()

	preview, err := ctl.PreviewSubscription(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := ctl.AddSubscription(SubInput{Token: preview.Token, Enabled: true, Interval: "manual"})
	if err != nil {
		t.Fatal(err)
	}
	placeholder := ctl.Profiles()[0]
	if placeholder.Host != "placeholder.example" || placeholder.Balance {
		t.Fatal("initial non-JSON response was not used")
	}
	available.Store(true)
	if _, err := ctl.UpdateSubscription(sub.ID); err != nil {
		t.Fatal(err)
	}
	profiles := ctl.Profiles()
	if len(profiles) != 2 || profiles[0].ID != placeholder.ID || !profiles[0].Balance || profiles[0].Host != "" {
		t.Fatalf("selectable balancer did not replace the placeholder: %+v", profiles)
	}
	if err := ctl.SetMain(placeholder.ID); err != nil {
		t.Fatal(err)
	}
	st := ctl.Settings()
	st.DefaultAction = rules.Tunnel
	if _, err := ctl.SaveSettings(st); err != nil {
		t.Fatal(err)
	}
	if err := ctl.Connect(); err != nil {
		t.Fatal(err)
	}
	running := (*sessions)[0].cfg.Profiles
	if len(running) != 1 || running[0].Balance == nil || len(running[0].Balance.Nodes) != 2 {
		t.Fatal("routing did not receive the selected balancer")
	}

	saved, err := ctl.Store.LoadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	b := saved.Find(placeholder.ID).Balance
	if b.Nodes[0].Settings.ID != "test-balance-secret-a" || b.Nodes[0].Fragment.Packets != "tlshello" {
		t.Fatal("balancer lost its settings after saving")
	}
	stored, err := os.ReadFile(filepath.Join(ctl.Store.Dir, "profiles.json"))
	if err != nil || strings.Contains(string(stored), "test-balance-secret") {
		t.Fatal("balancer IDs must be sealed on disk")
	}
	cfg, err := vless.BalanceConfig(*b, []netip.Addr{netip.MustParseAddr("192.0.2.4"), {}},
		vless.Run{SOCKSListen: "127.0.0.1:32000", SOCKSUsername: "user", SOCKSPassword: "pass"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct{ Outbounds []json.RawMessage }
	if err := json.Unmarshal(cfg, &decoded); err != nil || len(decoded.Outbounds) != 1 ||
		!strings.Contains(string(decoded.Outbounds[0]), "finalmask") ||
		strings.Contains(string(cfg), "0.0.0.0") || strings.Contains(string(cfg), "ignored.log") {
		t.Fatal("unexpected runtime config: must use only the reachable, sanitized outbound and HyRoute's SOCKS listener")
	}
	if _, err := ctl.ExportURI(placeholder.ID); err == nil {
		t.Fatal("a leastLoad profile cannot be exported as one VLESS URI")
	}
	available.Store(false)
	if _, err := ctl.UpdateSubscription(sub.ID); err == nil || !ctl.Profiles()[0].Balance {
		t.Fatal("an alternate format failure must keep the working profile")
	}
}

func TestSubscriptionIgnoresAlternateJSONWithoutBalancer(t *testing.T) {
	ctl, _ := newCtl(t)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Profile-Web-Page-Url", "https://example.org/subscription")
		if strings.HasPrefix(req.UserAgent(), "Happ/") {
			fmt.Fprint(w, `{"outbounds":[]}`)
			return
		}
		fmt.Fprint(w, "vless://test-user@a.example:443?security=tls#A")
	}))
	defer s.Close()
	orig := directTransport
	directTransport = s.Client().Transport.(*http.Transport).Clone()
	defer func() {
		directTransport.CloseIdleConnections()
		directTransport = orig
	}()
	f, err := ctl.httpFetch(context.Background(), s.URL)
	if err != nil || !strings.HasPrefix(string(f.Body), "vless://") {
		t.Fatal("the original link list must survive the format probe", err)
	}
}
