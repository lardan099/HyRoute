package rules

import (
	"reflect"
	"testing"
)

// fillRefs gives every nil slice and pointer reachable from v (a struct)
// one element, so a shallow copy would share it.
func fillRefs(v reflect.Value) {
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		switch f.Kind() {
		case reflect.Slice:
			if f.Len() == 0 {
				f.Set(reflect.MakeSlice(f.Type(), 1, 1))
			}
			if e := f.Index(0); e.Kind() == reflect.Struct {
				fillRefs(e)
			}
		case reflect.Pointer:
			if f.IsNil() {
				f.Set(reflect.New(f.Type().Elem()))
			}
			if e := f.Elem(); e.Kind() == reflect.Struct {
				fillRefs(e)
			}
		case reflect.Struct:
			fillRefs(f)
		}
	}
}

// sharedRef names the first slice or pointer field that a and b share.
func sharedRef(a, b reflect.Value, path string) string {
	for i := 0; i < a.NumField(); i++ {
		fa, fb := a.Field(i), b.Field(i)
		name := path + "." + a.Type().Field(i).Name
		switch fa.Kind() {
		case reflect.Slice:
			if fa.Len() > 0 && fa.Pointer() == fb.Pointer() {
				return name
			}
			for j := 0; j < fa.Len() && j < fb.Len(); j++ {
				if fa.Index(j).Kind() == reflect.Struct {
					if s := sharedRef(fa.Index(j), fb.Index(j), name); s != "" {
						return s
					}
				}
			}
		case reflect.Pointer:
			if !fa.IsNil() && fa.Pointer() == fb.Pointer() {
				return name
			}
			if !fa.IsNil() && !fb.IsNil() && fa.Elem().Kind() == reflect.Struct {
				if s := sharedRef(fa.Elem(), fb.Elem(), name); s != "" {
					return s
				}
			}
		case reflect.Struct:
			if s := sharedRef(fa, fb, name); s != "" {
				return s
			}
		}
	}
	return ""
}

// TestCloneShares: Config.Clone shares no slice or pointer with the
// original, including fields added to Rule later; the copy is equal.
func TestCloneShares(t *testing.T) {
	var c Config
	fillRefs(reflect.ValueOf(&c).Elem())
	d := c.Clone()
	if !reflect.DeepEqual(c, d) {
		t.Fatalf("clone differs: %#v", d)
	}
	if s := sharedRef(reflect.ValueOf(c), reflect.ValueOf(d), "Config"); s != "" {
		t.Fatalf("%s is shared", s)
	}
	if (Config{}).Clone().Rules != nil || (Config{Rules: []Rule{}}).Clone().Rules == nil {
		t.Fatal("nil and empty rule lists are not kept")
	}
}
