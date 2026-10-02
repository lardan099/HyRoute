package apply

import (
	"strings"
	"testing"
)

// A renamed outbound keeps its password: the check shows it hidden, not
// as a new value.
func TestMaskRenamedOutbound(t *testing.T) {
	current := deployed + `outbounds:
  - name: proxy
    type: socks5
    socks5:
      addr: 203.0.113.5:1080
      password: fake-renamed-pass
`
	cand := strings.Replace(current, "name: proxy", "name: nl", 1)
	ch, out, err := Build([]byte(current), cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fake-renamed-pass") {
		t.Fatalf("candidate lost the password:\n%s", out)
	}
	if strings.Contains(ch.YAML, "fake-renamed-pass") {
		t.Fatalf("shown:\n%s", ch.YAML)
	}
	for _, l := range ch.Diff {
		if strings.Contains(l.Text, "fake-renamed-pass") {
			t.Fatalf("in the diff: %+v", l)
		}
	}
}
