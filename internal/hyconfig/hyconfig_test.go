package hyconfig

import (
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseServer(t *testing.T, b []byte) *Server {
	t.Helper()
	s, err := ParseServer(b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func marshal(t *testing.T, v interface{ Marshal() ([]byte, error) }) string {
	t.Helper()
	b, err := v.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// generic is the document as plain maps and lists: what any YAML reader
// (Hysteria's viper included) sees, with keys lowercased like viper does.
func generic(t *testing.T, b []byte) any {
	t.Helper()
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return lowerKeys(v)
}

func lowerKeys(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := map[string]any{}
		for k, e := range x {
			m[strings.ToLower(k)] = lowerKeys(e)
		}
		return m
	case []any:
		for i := range x {
			x[i] = lowerKeys(x[i])
		}
	}
	return v
}

// dropFalse removes false and empty values, which the model does not
// write (they are Hysteria's defaults).
func dropFalse(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			e = dropFalse(e)
			if e == false || e == nil {
				delete(x, k)
				continue
			}
			if m, ok := e.(map[string]any); ok && len(m) == 0 {
				delete(x, k)
				continue
			}
			x[k] = e
		}
	case []any:
		for i := range x {
			x[i] = dropFalse(x[i])
		}
	}
	return v
}

func TestRoundTripKeepsEveryField(t *testing.T) {
	for _, name := range []string{"server-full.yaml", "server-acme.yaml", "server-future.yaml"} {
		t.Run(name, func(t *testing.T) {
			in := readFile(t, name)
			s := parseServer(t, in)
			out := marshal(t, s)
			if got, want := dropFalse(generic(t, []byte(out))), dropFalse(generic(t, in)); !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip changed the document\n got: %v\nwant: %v\n%s", got, want, out)
			}
			// A second pass is byte-for-byte stable.
			if again := marshal(t, parseServer(t, []byte(out))); again != out {
				t.Fatalf("not stable:\n%s\n---\n%s", out, again)
			}
		})
	}
}

func TestDocumentedFieldsAreKnown(t *testing.T) {
	for _, name := range []string{"server-full.yaml", "server-acme.yaml"} {
		if u := UnknownFields(parseServer(t, readFile(t, name))); len(u) != 0 {
			t.Errorf("%s: unknown %v", name, u)
		}
	}
	c, err := ParseClient(readFile(t, "client-full.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if u := UnknownFields(c); !slices.Equal(u, []string{"tcpForwarding", "tun"}) {
		t.Errorf("client unknown %v", u)
	}
}

func TestUnknownFieldsKeptInPlace(t *testing.T) {
	s := parseServer(t, readFile(t, "server-future.yaml"))
	// In output order: nested levels with the known fields, then the
	// level's own unknown keys.
	want := []string{"tls.futureTLSOption", "quic.futureQUICKnob", "outbounds[0].direct.futureDirectOption", "outbounds[0].futureOutboundOption", "futureTopLevel", "anotherFutureKey"}
	if got := UnknownFields(s); !slices.Equal(got, want) {
		t.Fatalf("unknown fields %v, want %v", got, want)
	}
	if s.Listen != ":443" || s.QUIC.MaxIdleTimeout != "30s" || s.Outbounds[0].Direct.Mode != "auto" {
		t.Fatalf("known fields next to unknown ones: %+v", s)
	}
	out := marshal(t, s)
	for _, frag := range []string{
		"listen: :443\n",
		"futureTLSOption: 42",
		"futureQUICKnob: fast",
		"futureDirectOption: [a, b]",
		"nested: [1, 2, 3]",
		"udpIdleTimeout: 60000000000\n", // an integer stays an integer
		`anotherFutureKey: "last"`,
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("output lacks %q:\n%s", frag, out)
		}
	}
	// Unknown keys go after the known ones, in their original order.
	if i, j := strings.Index(out, "futureTopLevel"), strings.Index(out, "anotherFutureKey"); i < strings.Index(out, "outbounds:") || j < i {
		t.Errorf("unknown keys out of order:\n%s", out)
	}
}

func TestEditKeepsUnknown(t *testing.T) {
	s := parseServer(t, readFile(t, "server-future.yaml"))
	s.Auth.Password = "fake-new-password"
	s.Obfs = Obfs{Type: "salamander", Salamander: Salamander{Password: "fake-obfs-password"}}
	out := marshal(t, s)
	back := parseServer(t, []byte(out))
	if back.Auth.Password != "fake-new-password" || back.Obfs.Salamander.Password != "fake-obfs-password" {
		t.Fatalf("edit lost: %+v", back)
	}
	if len(UnknownFields(back)) != 6 {
		t.Fatalf("unknown fields after edit: %v", UnknownFields(back))
	}
}

func TestParseErrors(t *testing.T) {
	for name, in := range map[string]string{
		"empty":       "",
		"comment":     "# nothing\n",
		"scalar":      "just text\n",
		"list":        "- a\n- b\n",
		"duplicate":   "listen: :443\nListen: :8443\n",
		"two docs":    "listen: :443\n---\nlisten: :8443\n",
		"bad type":    "quic:\n  maxIncomingStreams: many\n",
		"section":     "tls: yes\n",
		"merge":       "base: &b {listen: ':443'}\n<<: *b\n",
		"broken yaml": "listen: [\n",
	} {
		if _, err := ParseServer([]byte(in)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// An empty section is simply empty.
	s, err := ParseServer([]byte("quic:\nauth:\n  type: password\n  password: fake-auth-password\n"))
	if err != nil || s.Auth.Password == "" {
		t.Fatalf("%v %+v", err, s)
	}
}

func TestAliasesResolve(t *testing.T) {
	s := parseServer(t, []byte("x-auth: &a\n  type: password\n  password: fake-auth-password\nauth: *a\n"))
	if s.Auth.Type != "password" || s.Auth.Password != "fake-auth-password" {
		t.Fatalf("%+v", s.Auth)
	}
}

func TestAliasIntoKnownField(t *testing.T) {
	s := parseServer(t, []byte("auth: &a\n  type: password\n  password: fake-auth-password\nx-copy: *a\n"))
	out := marshal(t, s)
	back := parseServer(t, []byte(out))
	if !strings.Contains(out, "x-copy:\n  type: password") || back.Auth.Password != "fake-auth-password" {
		t.Fatalf("%s", out)
	}
	bomb := "a: &a [x, x, x, x, x, x, x, x, x, x]\nb: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\nc: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\nd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\ne: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]\n"
	if _, err := ParseServer([]byte(bomb)); err == nil {
		t.Fatal("alias bomb accepted")
	}
}

func TestClientRoundTrip(t *testing.T) {
	in := readFile(t, "client-full.yaml")
	c, err := ParseClient(in)
	if err != nil {
		t.Fatal(err)
	}
	out := marshal(t, c)
	if got, want := dropFalse(generic(t, []byte(out))), dropFalse(generic(t, in)); !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip changed the document\n got: %v\nwant: %v", got, want)
	}
}

// Every struct reachable from Server and Client must keep unknown keys:
// a new type without the YAML methods would silently drop them.
func TestAllModelTypesKeepUnknown(t *testing.T) {
	um := reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()
	m := reflect.TypeOf((*yaml.Marshaler)(nil)).Elem()
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(tp reflect.Type) {
		for tp.Kind() == reflect.Pointer || tp.Kind() == reflect.Slice {
			tp = tp.Elem()
		}
		if tp.Kind() != reflect.Struct || seen[tp] {
			return
		}
		seen[tp] = true
		if f, ok := tp.FieldByName("Unknown"); !ok || f.Type != unknownType {
			t.Errorf("%s has no Unknown field", tp.Name())
		}
		if !reflect.PointerTo(tp).Implements(um) || !tp.Implements(m) {
			t.Errorf("%s lacks the YAML methods", tp.Name())
		}
		for i := 0; i < tp.NumField(); i++ {
			if tp.Field(i).Type != unknownType {
				walk(tp.Field(i).Type)
			}
		}
	}
	walk(reflect.TypeOf(Server{}))
	walk(reflect.TypeOf(Client{}))
	if len(seen) != 39 {
		t.Errorf("walked %d types", len(seen))
	}
}

// Whatever parses must write back to something that parses to the same
// output.
func FuzzServerRoundTrip(f *testing.F) {
	for _, name := range []string{"server-full.yaml", "server-acme.yaml", "server-future.yaml"} {
		b, err := os.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseServer(b)
		if err != nil {
			return
		}
		s.Validate()
		out, err := s.Marshal()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s2, err := ParseServer(out)
		if err != nil {
			t.Fatalf("reparse: %v\n%s", err, out)
		}
		out2, err := s2.Marshal()
		if err != nil || string(out2) != string(out) {
			t.Fatalf("unstable: %v\n%s\n---\n%s", err, out, out2)
		}
	})
}
