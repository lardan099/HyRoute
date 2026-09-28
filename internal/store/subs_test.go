package store

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// Pushing the current body again keeps the previous snapshot.
func TestPushSnapshotSameBodyKeepsPrevious(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{"good", "bad", "bad"} {
		if err := s.PushSnapshot("x", []byte(b), nil); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "good" {
		t.Fatalf("%q %v", got, err)
	}
}

// A body the caller calls the same as the current one (the same servers,
// other names) replaces the current snapshot and keeps the previous one.
func TestPushSnapshotSameServersKeepsPrevious(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	same := func(cur []byte) bool { return strings.HasPrefix(string(cur), "bad") }
	for _, b := range []string{"good", "bad 4.3GB", "bad 4.1GB"} {
		if err := s.PushSnapshot("x", []byte(b), same); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "good" {
		t.Fatalf("previous %q %v", got, err)
	}
	if err := s.SwapSnapshots("x"); err != nil {
		t.Fatal(err)
	}
	if got, err := s.PreviousSnapshot("x"); err != nil || string(got) != "bad 4.1GB" {
		t.Fatalf("after swap %q %v", got, err)
	}
}

// subinfo: infoAt and supportUrl survive a save and a load, are absent
// from the file while unused, and an oversized support link is dropped.
func TestSubscriptionInfoRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 9, 28, 14, 5, 0, 0, time.UTC)
	plain := Subscription{ID: "a", Name: "plain", URL: "https://p.example/sub/x", UserInfo: "upload=1"}
	info := Subscription{ID: "b", Name: "info", URL: "https://p.example/sub/y", UserInfo: "upload=1; total=2", InfoAt: at, Support: "https://t.me/some_support"}
	if err := s.SaveSubscriptions([]Subscription{plain}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.path("subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "infoAt") || strings.Contains(string(b), "supportUrl") {
		t.Fatalf("unused keys written:\n%s", b)
	}
	if err := s.SaveSubscriptions([]Subscription{plain, info}); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSubscriptions()
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	if !got[1].InfoAt.Equal(at) || got[1].Support != info.Support || got[1].URL != info.URL || !got[0].InfoAt.IsZero() || got[0].Support != "" {
		t.Fatalf("%+v", got)
	}

	// A support link longer than the bound is dropped on load.
	info.Support = "https://t.me/" + strings.Repeat("a", maxSupportURL-len("https://t.me/")+1)
	if err := s.SaveSubscriptions([]Subscription{info}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.LoadSubscriptions(); err != nil || got[0].Support != "" || !got[0].InfoAt.Equal(at) {
		t.Fatalf("%+v %v", got, err)
	}
}

// subinfo: a file of v1.0.0 (no new keys, a raw userInfo) loads, and a new
// file still reads into the v1.0.0 shape with its URL.
func TestSubscriptionsFileV1Compat(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := seal([]byte("https://p.example/sub/tok"))
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.StdEncoding.EncodeToString(sealed)
	v1 := `[
  {
    "id": "k3",
    "name": "My VPN",
    "enabled": true,
    "interval": "24h",
    "lastUpdate": "2026-09-01T10:00:00+03:00",
    "lastAttempt": "2026-09-01T10:00:00+03:00",
    "lastError": "",
    "count": 2,
    "ignored": null,
    "warnings": null,
    "userInfo": "Download=5 ;upload=1,total=10",
    "hasPrevious": false,
    "sealedURL": "` + enc + `"
  }
]`
	if err := os.WriteFile(s.path("subscriptions.json"), []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadSubscriptions()
	if err != nil || len(got) != 1 || got[0].UserInfo != "Download=5 ;upload=1,total=10" || !got[0].InfoAt.IsZero() || got[0].URL != "https://p.example/sub/tok" {
		t.Fatalf("%+v %v", got, err)
	}

	// The v1.0.0 storedSub, verbatim.
	type v1Subscription struct {
		ID          string         `json:"id"`
		Name        string         `json:"name"`
		URL         string         `json:"-"`
		Enabled     bool           `json:"enabled"`
		Interval    string         `json:"interval"`
		LastUpdate  time.Time      `json:"lastUpdate"`
		LastAttempt time.Time      `json:"lastAttempt"`
		LastError   string         `json:"lastError"`
		Count       int            `json:"count"`
		Ignored     map[string]int `json:"ignored"`
		Warnings    []string       `json:"warnings"`
		UserInfo    string         `json:"userInfo"`
		HasPrevious bool           `json:"hasPrevious"`
	}
	type v1Stored struct {
		v1Subscription
		SealedURL string `json:"sealedURL"`
	}
	got[0].InfoAt, got[0].Support = time.Now(), "https://t.me/x"
	if err := s.SaveSubscriptions(got); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.path("subscriptions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var old []v1Stored
	if err := json.Unmarshal(b, &old); err != nil || len(old) != 1 || old[0].Name != "My VPN" {
		t.Fatalf("%+v %v", old, err)
	}
	raw, err := base64.StdEncoding.DecodeString(old[0].SealedURL)
	if err == nil {
		raw, err = unseal(raw)
	}
	if err != nil || string(raw) != "https://p.example/sub/tok" {
		t.Fatalf("%q %v", raw, err)
	}
}
