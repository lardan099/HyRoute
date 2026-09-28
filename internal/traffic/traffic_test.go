package traffic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func at(s *Stats, t time.Time) { s.now = func() time.Time { return t } }

func TestAddReportPersist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traffic.json")
	s := Open(path)
	day := time.Date(2026, 9, 28, 14, 30, 0, 0, time.Local)
	at(s, day.AddDate(0, 0, -1))
	s.Add("de", "Германия", "chrome.exe", 100, 1000)
	at(s, day)
	s.Add("de", "Германия", "chrome.exe", 10, 20)
	s.Add("nl", "Нидерланды", "Discord.exe", 1, 2)
	s.Add("nl", "Нидерланды", "", 0, 0) // nothing
	s.Add("", "", "x.exe", 5, 5)        // no server: not counted
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}

	s = Open(path)
	at(s, day)
	r := s.Report("day", nil)
	if r.Total != (Pair{11, 22}) || len(r.Servers) != 2 || r.Servers[0].ID != "de" || r.Servers[0].Name != "Германия" {
		t.Fatalf("%+v", r)
	}
	if len(r.Series) != 15 || r.Series[14].Label != "14" || r.Series[14].Total() != 33 || r.Series[13].Total() != 0 {
		t.Fatalf("%+v", r.Series)
	}
	w := s.Report("week", func(id string) string {
		if id == "nl" {
			return "NL new"
		}
		return id // deleted: the stored name
	})
	if w.Total != (Pair{111, 1022}) || len(w.Series) != 7 || w.Series[5].Total() != 1100 || w.Since != "2026-09-27" {
		t.Fatalf("%+v", w)
	}
	if w.Servers[0].Name != "Германия" || w.Servers[1].Name != "NL new" || w.Apps[0].ID != "chrome.exe" || w.Apps[0].Total() != 1130 {
		t.Fatalf("%+v", w)
	}

	// Nothing about sites is in the file.
	b, _ := os.ReadFile(path)
	for _, bad := range []string{"http", ".com", "443"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("%s in %s", bad, b)
		}
	}

	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if r := s.Report("year", nil); r.Total.Total() != 0 || r.Since != "" {
		t.Fatalf("%+v", r)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestRetention(t *testing.T) {
	s := Open(filepath.Join(t.TempDir(), "t.json"))
	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.Local)
	at(s, start)
	s.Add("de", "DE", "a.exe", 1, 1)
	at(s, start.AddDate(0, 0, 100))
	s.Add("de", "DE", "b.exe", 1, 1)
	if d := s.f.Days["2025-01-01"]; d == nil || d.Apps != nil || d.Servers["de"].Total() != 2 {
		t.Fatalf("%+v", d)
	}
	if len(s.f.Hours) != 1 {
		t.Fatalf("%v", s.f.Hours)
	}
	r := s.Report("year", nil)
	if r.AppsFrom == "" || len(r.Apps) != 1 || r.Total.Total() != 4 {
		t.Fatalf("%+v", r)
	}
	at(s, start.AddDate(0, 0, 501))
	s.Add("nl", "NL", "c.exe", 1, 1)
	if len(s.f.Days) != 1 || s.f.Names["de"] != "" {
		t.Fatalf("%+v %v", s.f.Days, s.f.Names)
	}
}

func TestBrokenFileStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	os.WriteFile(path, []byte("{nope"), 0o644)
	s := Open(path)
	s.Add("de", "DE", "a.exe", 1, 1)
	if s.Report("day", nil).Total.Total() != 2 {
		t.Fatal("not counted")
	}
}
