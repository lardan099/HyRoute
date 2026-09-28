package dnscache

import (
	"errors"
	"reflect"
	"testing"
)

// dns: answers to HyRoute's own queries are taken only when they repeat
// the query's ID and question.
func TestAddAnswerFor(t *testing.T) {
	c, _ := newCache()
	a := response(t, "WWW.example.com.", ans{name: "www.example.com.", ip: "93.184.216.34", ttl: 300})
	// DoH: ID 0 on both sides; the question's case may differ (0x20).
	if n, err := c.AddAnswerFor(query(t, 0, "www.Example.com."), a); n != 1 || err != nil {
		t.Fatalf("%d %v", n, err)
	}
	if got := c.Names(ip("93.184.216.34")); !reflect.DeepEqual(got, []string{"www.example.com"}) {
		t.Fatal(got)
	}
	c2, _ := newCache()
	for label, fn := range map[string]func() (int, error){
		"other ID":        func() (int, error) { return c2.AddAnswerFor(query(t, 7, "www.example.com."), a) },
		"other name":      func() (int, error) { return c2.AddAnswerFor(query(t, 0, "evil.example."), a) },
		"answer as query": func() (int, error) { return c2.AddAnswerFor(a, a) },
		"query as answer": func() (int, error) {
			return c2.AddAnswerFor(query(t, 0, "www.example.com."), query(t, 0, "www.example.com."))
		},
		"garbage": func() (int, error) { return c2.AddAnswerFor([]byte{1}, []byte{2}) },
	} {
		if n, err := fn(); n != 0 || err == nil {
			t.Errorf("%s: %d %v", label, n, err)
		}
	}
	if _, err := c2.AddAnswerFor(query(t, 7, "www.example.com."), a); !errors.Is(err, ErrUnsolicited) {
		t.Fatal(err)
	}
	if c2.Len() != 0 {
		t.Fatal("cache changed by a mismatch")
	}
	// A TCP pass-through: the client's own ID.
	if n, err := c2.AddAnswerFor(query(t, 0x4242, "www.example.com."), withID(a, 0x4242)); n != 1 || err != nil {
		t.Fatalf("TCP: %d %v", n, err)
	}
}
