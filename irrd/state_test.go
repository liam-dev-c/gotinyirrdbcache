package irrd

import (
	"testing"
)

func TestState_Macros(t *testing.T) {
	state := NewWhoisCacheState()
	state.ApplyUpdate(Update{Action: "ADD", Serial: "2", Record: Macro{Name: "A", Members: []string{"a", "b"}}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "3", Record: Macro{Name: "B", Members: []string{"b", "c"}}})

	if len(state.Macros) != 2 {
		t.Fatalf("expected 2 macros, got %d", len(state.Macros))
	}
	assertStringSet(t, state.Macros["A"], []string{"a", "b"})
	assertStringSet(t, state.Macros["B"], []string{"b", "c"})
	if state.Serial != "3" {
		t.Errorf("expected serial 3, got %s", state.Serial)
	}

	// Delete B
	state.ApplyUpdate(Update{Action: "DEL", Serial: "4", Record: Macro{Name: "B", Members: nil}})
	if len(state.Macros) != 1 {
		t.Fatalf("expected 1 macro after DEL, got %d", len(state.Macros))
	}
	assertStringSet(t, state.Macros["A"], []string{"a", "b"})
	if state.Serial != "4" {
		t.Errorf("expected serial 4, got %s", state.Serial)
	}
}

func TestState_Prefix4(t *testing.T) {
	state := NewWhoisCacheState()
	state.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Route{Prefix: "abc", Origin: "asn1"}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "2", Record: Route{Prefix: "bcd", Origin: "asn2"}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "3", Record: Route{Prefix: "def", Origin: "asn1"}})
	state.ApplyUpdate(Update{Action: "DEL", Serial: "4", Record: Route{Prefix: "abc", Origin: "asn1"}})

	if len(state.Prefix4) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(state.Prefix4))
	}
	assertStringSet(t, state.Prefix4["asn1"], []string{"def"})
	assertStringSet(t, state.Prefix4["asn2"], []string{"bcd"})

	// Delete last prefix for asn2
	state.ApplyUpdate(Update{Action: "DEL", Serial: "5", Record: Route{Prefix: "bcd", Origin: "asn2"}})
	if len(state.Prefix4) != 1 {
		t.Fatalf("expected 1 origin after cleanup, got %d", len(state.Prefix4))
	}
	assertStringSet(t, state.Prefix4["asn1"], []string{"def"})
}

func TestState_Prefix6(t *testing.T) {
	state := NewWhoisCacheState()
	state.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Route6{Prefix: "abc", Origin: "asn1"}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "2", Record: Route6{Prefix: "bcd", Origin: "asn2"}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "3", Record: Route6{Prefix: "def", Origin: "asn1"}})
	state.ApplyUpdate(Update{Action: "DEL", Serial: "4", Record: Route6{Prefix: "abc", Origin: "asn1"}})

	if len(state.Prefix6) != 2 {
		t.Fatalf("expected 2 origins, got %d", len(state.Prefix6))
	}
	assertStringSet(t, state.Prefix6["asn1"], []string{"def"})
	assertStringSet(t, state.Prefix6["asn2"], []string{"bcd"})

	// Delete last prefix for asn2
	state.ApplyUpdate(Update{Action: "DEL", Serial: "5", Record: Route6{Prefix: "bcd", Origin: "asn2"}})
	if len(state.Prefix6) != 1 {
		t.Fatalf("expected 1 origin after cleanup, got %d", len(state.Prefix6))
	}
	assertStringSet(t, state.Prefix6["asn1"], []string{"def"})
}

func TestState_Unrecognised(t *testing.T) {
	state := NewWhoisCacheState()
	// Should not panic
	state.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Unrecognised{Key: "mntner"}})
	if state.Serial != "1" {
		t.Errorf("expected serial 1, got %s", state.Serial)
	}
}

func TestState_UpdatedAt(t *testing.T) {
	state := NewWhoisCacheState()
	if !state.UpdatedAt.IsZero() {
		t.Error("expected zero UpdatedAt initially")
	}
	state.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Route{Prefix: "x", Origin: "y"}})
	if state.UpdatedAt.IsZero() {
		t.Error("expected non-zero UpdatedAt after update")
	}
}

// assertStringSet checks that a StringSet contains exactly the expected values.
func assertStringSet(t *testing.T, s StringSet, expected []string) {
	t.Helper()
	if len(s) != len(expected) {
		t.Errorf("expected set of size %d, got %d: %v", len(expected), len(s), s)
		return
	}
	for _, v := range expected {
		if !s.Contains(v) {
			t.Errorf("expected set to contain %q, got %v", v, s)
		}
	}
}
