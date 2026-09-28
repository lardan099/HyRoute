package ctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	for _, s := range []string{`{"v":1}`, strings.Repeat("я", 1000)} {
		if err := WriteFrame(&b, []byte(s), 1<<20); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{`{"v":1}`, strings.Repeat("я", 1000)} {
		got, err := ReadFrame(&b, 1<<20)
		if err != nil || string(got) != s {
			t.Fatal(err)
		}
	}
	if _, err := ReadFrame(&b, 10); err != io.EOF {
		t.Fatal(err)
	}
}

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestFrameLimits(t *testing.T) {
	for _, n := range []uint32{0, 101} {
		raw := append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, bytes.Repeat([]byte("x"), 200)...)
		cr := &countingReader{r: bytes.NewReader(raw)}
		_, err := ReadFrame(cr, 100)
		var tb *ErrFrameTooBig
		if !errors.As(err, &tb) || tb.N != int(n) || cr.n != 4 {
			t.Fatalf("length %d: %v, read %d", n, err, cr.n)
		}
	}
	// A truncated body.
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 0, 0, 5, 'a'}), 100); err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	// Writing over the limit writes nothing.
	var b bytes.Buffer
	if err := WriteFrame(&b, make([]byte, 11), 10); err == nil || b.Len() != 0 {
		t.Fatal(err, b.Len())
	}
}

func TestASCIIJSON(t *testing.T) {
	in := map[string]string{"ru": "Привет", "flag": "\U0001F1E9\U0001F1EA DE", "ls": "a\u2028b", "ctl": "a\x01\tb", "q": `"\`}
	raw, _ := json.Marshal(in)
	out := ASCIIJSON(raw)
	for _, c := range out {
		if c >= 0x80 {
			t.Fatalf("non-ASCII byte in %s", out)
		}
	}
	if !bytes.Contains(out, []byte(`ud83c`)) || !bytes.Contains(out, []byte(`udde9`)) {
		t.Fatalf("no surrogate pair: %s", out)
	}
	var back map[string]string
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	for k, v := range in {
		if back[k] != v {
			t.Fatalf("%s: %q != %q", k, back[k], v)
		}
	}
	// Already escaped input stays as it is.
	if s := string(ASCIIJSON(out)); s != string(out) {
		t.Fatal(s)
	}
}

func TestExitCodes(t *testing.T) {
	want := map[string]int{
		CodeFailed: 1, CodeBusy: 1, CodeDropped: 1, "new-code": 1,
		CodeUsage: 2, CodeTooBig: 2,
		CodeNotRunning: 3,
		CodeDenied:     4, CodeOff: 4, CodeReadOnly: 4, CodeOtherUser: 4, CodeImpostor: 4,
		CodeTimeout: 5, CodeStarting: 5,
		CodeRules:   6,
		CodeUnknown: 7, CodeUnknownArg: 7, CodeVersion: 7, CodeProtoOld: 7, CodeProtoNew: 7,
		CodeInterrupted: 130,
	}
	for code, exit := range want {
		if got := ExitCode(code); got != exit {
			t.Errorf("%s: %d, want %d", code, got, exit)
		}
	}
}

func TestNames(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	if got := PipeName(sid); got != `\\.\pipe\HyRoute-7f3c1a52-ctl-S-1-5-21-1-2-3-1001` {
		t.Fatal(got)
	}
	if got := RunEventName(sid); got != `Global\HyRoute-7f3c1a52-run-S-1-5-21-1-2-3-1001` {
		t.Fatal(got)
	}
}

func TestEncodeRequestNoEscaping(t *testing.T) {
	b, err := EncodeRequest(Request{V: 1, Cmd: "rules-import", Args: json.RawMessage(`{"content":"a -> b <c> & я"}`)})
	if err != nil || !bytes.Contains(b, []byte("a -> b <c> & я")) || bytes.HasSuffix(b, []byte("\n")) {
		t.Fatalf("%s %v", b, err)
	}
}
