package irrd

import (
	"testing"
)

func TestMacroFields(t *testing.T) {
	m := Macro{Name: "AS-FOO", Members: []string{"AS1", "AS2"}}
	if m.Name != "AS-FOO" {
		t.Errorf("expected Name AS-FOO, got %s", m.Name)
	}
	if len(m.Members) != 2 || m.Members[0] != "AS1" || m.Members[1] != "AS2" {
		t.Errorf("unexpected Members: %v", m.Members)
	}
}

func TestRouteFields(t *testing.T) {
	r := Route{Prefix: "1.2.3.0/24", Origin: "AS123"}
	if r.Prefix != "1.2.3.0/24" {
		t.Errorf("expected Prefix 1.2.3.0/24, got %s", r.Prefix)
	}
	if r.Origin != "AS123" {
		t.Errorf("expected Origin AS123, got %s", r.Origin)
	}
}

func TestRoute6Fields(t *testing.T) {
	r := Route6{Prefix: "2001:db8::/32", Origin: "AS456"}
	if r.Prefix != "2001:db8::/32" {
		t.Errorf("expected Prefix 2001:db8::/32, got %s", r.Prefix)
	}
	if r.Origin != "AS456" {
		t.Errorf("expected Origin AS456, got %s", r.Origin)
	}
}

func TestUnrecognisedFields(t *testing.T) {
	u := Unrecognised{Key: "mntner"}
	if u.Key != "mntner" {
		t.Errorf("expected Key mntner, got %s", u.Key)
	}
}

func TestRecordInterface(t *testing.T) {
	var _ Record = Macro{}
	var _ Record = Route{}
	var _ Record = Route6{}
	var _ Record = Unrecognised{}
}

func TestRecordType(t *testing.T) {
	cases := []struct {
		rec      Record
		expected string
	}{
		{Macro{}, "macro"},
		{Route{}, "route"},
		{Route6{}, "route6"},
		{Unrecognised{}, "unrecognised"},
	}
	for _, tc := range cases {
		if got := tc.rec.recordType(); got != tc.expected {
			t.Errorf("%T.recordType() = %q, want %q", tc.rec, got, tc.expected)
		}
	}
}
