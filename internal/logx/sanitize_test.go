package logx

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSanitize(t *testing.T) {
	// testdata/sanitize.json is shared with the frontend
	// (frontend/scripts/privacy-check.mjs): the UI masks the same.
	b, err := os.ReadFile("testdata/sanitize.json")
	if err != nil {
		t.Fatal(err)
	}
	var shared struct {
		Hosts []string `json:"hosts"`
		Cases []struct{ In, Want string }
	}
	if err := json.Unmarshal(b, &shared); err != nil {
		t.Fatal(err)
	}
	for _, c := range shared.Cases {
		if got := Sanitize(c.In, shared.Hosts); got != c.Want {
			t.Errorf("%q:\n got %q\nwant %q", c.In, got, c.Want)
		}
	}
	// Go only: paths (the UI masks them where it shows one, hideUserPath).
	for in, want := range map[string]string{
		`from C:\Users\Иван\Downloads\HyRoute ok`: `from C:\Users\***\Downloads\HyRoute ok`,
	} {
		if got := Sanitize(in, []string{"vpn.example.com"}); got != want {
			t.Errorf("%q:\n got %q\nwant %q", in, got, want)
		}
	}
}

// Long dotted runs that are not names (a.a.….com9) must not make MaskDomains
// retry every label and every prefix: exported logs have no line limit.
func TestMaskDomainsLong(t *testing.T) {
	x := strings.Repeat("x", 62)
	cases := map[string]string{
		strings.Repeat("a.", 5000) + "com9":           strings.Repeat("a.", 5000) + "com9",
		"sni=" + strings.Repeat("x1.", 3000) + "io0":  "sni=" + strings.Repeat("x1.", 3000) + "io0",
		strings.Repeat("a1-b.", 3000) + "c9":          strings.Repeat("a1-b.", 3000) + "c9",
		strings.Repeat("ab-c.", 3000) + "d9":          "***.ab-c.d9",
		strings.Repeat("ab.", 3000) + "com9 end":      "***.ab.com9 end",
		"_" + x + strings.Repeat(".a", 5000) + ".com": "_" + x + ".***.com",
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for in, want := range cases {
			if got := MaskDomains(in); got != want {
				t.Errorf("%.40q…: got %.60q…", in, got)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("MaskDomains takes too long on long dotted runs")
	}
}
