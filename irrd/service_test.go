package irrd

import (
	"testing"
)

func makeStateWithData() *WhoisCacheState {
	state := NewWhoisCacheState()
	state.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Macro{Name: "AS-FOO", Members: []string{"AS1", "AS2"}}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "2", Record: Route{Prefix: "1.0.0.0/8", Origin: "AS1"}})
	state.ApplyUpdate(Update{Action: "ADD", Serial: "3", Record: Route6{Prefix: "2001::/32", Origin: "AS1"}})
	return state
}

func TestWhoisCacheState_CacheStateProvider(t *testing.T) {
	state := makeStateWithData()
	state.Serial = "42"

	if state.GetSerial() != "42" {
		t.Errorf("GetSerial() = %q, want 42", state.GetSerial())
	}
	if state.GetUpdatedAt() == "" {
		t.Error("GetUpdatedAt() should not be empty")
	}
}

func TestDirectMap_Macros(t *testing.T) {
	state := makeStateWithData()
	acc := state.GetMacros()

	vals, ok := acc.Lookup("AS-FOO")
	if !ok {
		t.Fatal("expected AS-FOO to be found")
	}
	if len(vals) != 2 || vals[0] != "AS1" || vals[1] != "AS2" {
		t.Errorf("unexpected vals: %v", vals)
	}

	_, ok = acc.Lookup("missing")
	if ok {
		t.Error("expected missing key to return false")
	}

	keys := acc.Keys()
	if len(keys) != 1 || keys[0] != "AS-FOO" {
		t.Errorf("unexpected keys: %v", keys)
	}

	items := acc.Items()
	if len(items) != 1 || items[0].Key != "AS-FOO" {
		t.Errorf("unexpected items: %v", items)
	}
}

func TestDirectMap_Prefix4(t *testing.T) {
	state := makeStateWithData()
	acc := state.GetPrefix4()

	vals, ok := acc.Lookup("AS1")
	if !ok || len(vals) != 1 || vals[0] != "1.0.0.0/8" {
		t.Errorf("unexpected prefix4 vals: %v (ok=%v)", vals, ok)
	}

	keys := acc.Keys()
	if len(keys) != 1 || keys[0] != "AS1" {
		t.Errorf("unexpected keys: %v", keys)
	}

	items := acc.Items()
	if len(items) != 1 || items[0].Key != "AS1" {
		t.Errorf("unexpected items: %v", items)
	}
}

func TestDirectMap_Prefix6(t *testing.T) {
	state := makeStateWithData()
	acc := state.GetPrefix6()

	vals, ok := acc.Lookup("AS1")
	if !ok || len(vals) != 1 || vals[0] != "2001::/32" {
		t.Errorf("unexpected prefix6 vals: %v (ok=%v)", vals, ok)
	}
}

func TestCacheStateCombiner_CacheStateProvider(t *testing.T) {
	s1 := makeStateWithData()
	s1.Serial = "10"
	s2 := NewWhoisCacheState()
	s2.ApplyUpdate(Update{Action: "ADD", Serial: "20", Record: Macro{Name: "AS-FOO", Members: []string{"AS3"}}})
	s2.ApplyUpdate(Update{Action: "ADD", Serial: "20", Record: Route{Prefix: "2.0.0.0/8", Origin: "AS2"}})

	combined := NewCacheStateCombiner(map[string]*WhoisCacheState{"a": s1, "b": s2})

	if combined.GetSerial() != "a:10,b:20" {
		t.Errorf("GetSerial() = %q, want a:10,b:20", combined.GetSerial())
	}
	if combined.GetUpdatedAt() == "" {
		t.Error("GetUpdatedAt() should not be empty")
	}
}

func TestCombinerMap_Macros(t *testing.T) {
	s1 := makeStateWithData()
	s2 := NewWhoisCacheState()
	s2.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Macro{Name: "AS-FOO", Members: []string{"AS3"}}})
	s2.ApplyUpdate(Update{Action: "ADD", Serial: "2", Record: Macro{Name: "AS-BAR", Members: []string{"AS4"}}})

	combined := NewCacheStateCombiner(map[string]*WhoisCacheState{"a": s1, "b": s2})
	acc := combined.GetMacros()

	// AS-FOO is in both sources — union of {AS1,AS2} and {AS3}
	vals, ok := acc.Lookup("AS-FOO")
	if !ok {
		t.Fatal("expected AS-FOO to be found")
	}
	if len(vals) != 3 {
		t.Errorf("expected 3 members for AS-FOO, got %v", vals)
	}

	_, ok = acc.Lookup("missing")
	if ok {
		t.Error("expected missing key to return false")
	}

	keys := acc.Keys()
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %v", keys)
	}

	items := acc.Items()
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
}

func TestCombinerMap_Prefix4(t *testing.T) {
	s1 := makeStateWithData()
	s2 := NewWhoisCacheState()
	s2.ApplyUpdate(Update{Action: "ADD", Serial: "1", Record: Route{Prefix: "2.0.0.0/8", Origin: "AS1"}})

	combined := NewCacheStateCombiner(map[string]*WhoisCacheState{"a": s1, "b": s2})
	acc := combined.GetPrefix4()

	vals, ok := acc.Lookup("AS1")
	if !ok || len(vals) != 2 {
		t.Errorf("expected 2 prefixes for AS1, got %v (ok=%v)", vals, ok)
	}

	keys := acc.Keys()
	if len(keys) != 1 || keys[0] != "AS1" {
		t.Errorf("unexpected keys: %v", keys)
	}

	items := acc.Items()
	if len(items) != 1 {
		t.Errorf("expected 1 item, got %d", len(items))
	}
}

func TestCombinerMap_Prefix6(t *testing.T) {
	s1 := makeStateWithData()
	combined := NewCacheStateCombiner(map[string]*WhoisCacheState{"a": s1})
	acc := combined.GetPrefix6()

	vals, ok := acc.Lookup("AS1")
	if !ok || len(vals) != 1 || vals[0] != "2001::/32" {
		t.Errorf("unexpected prefix6 vals: %v (ok=%v)", vals, ok)
	}

	_, ok = acc.Lookup("missing")
	if ok {
		t.Error("expected missing key to return false")
	}
}
