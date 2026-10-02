package apply

import (
	"strings"
	"testing"
)

// A renamed outbound keeps its password: a check whose text is only shown
// hides it, not as a new value.
func TestHideRenamedOutbound(t *testing.T) {
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
	if err := HideCurrent(&ch, []byte(current)); err != nil {
		t.Fatal(err)
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

// The editor's own text keeps a new secret that equals another current
// one: hiding it would make Unmask put back the old value of its path.
func TestEditorKeepsEqualSecret(t *testing.T) {
	current := deployed + "obfs:\n  type: salamander\n  salamander:\n    password: fake-obfs-old\n"
	cand := strings.Replace(current, "fake-obfs-old", "fake-apply-auth-pass", 1)
	ch, out, err := Build([]byte(current), cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ch.YAML, "fake-apply-auth-pass") || !strings.Contains(string(out), "password: fake-apply-auth-pass") {
		t.Fatalf("the new obfs password is hidden:\n%s", ch.YAML)
	}
	// The text sent back as is applies the same candidate.
	_, again, err := Build([]byte(current), ch.YAML, nil)
	if err != nil || string(again) != string(out) {
		t.Fatalf("%v\n%s\n---\n%s", err, again, out)
	}
}
