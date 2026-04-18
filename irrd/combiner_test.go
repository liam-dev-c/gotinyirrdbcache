package irrd

import (
	"sort"
	"testing"
)

func makeCombinerDict() ([]map[string]int, *CombinerDict[int]) {
	sources := []map[string]int{
		{"A": 10},
		{"A": 2, "B": 3},
	}
	combined := NewCombinerDict(sources, func(x, y int) int { return x*y + 1 })
	return sources, combined
}

func TestCombinerDict_Constructor(t *testing.T) {
	sources, combined := makeCombinerDict()
	if len(combined.Sources) != len(sources) {
		t.Fatalf("expected %d sources, got %d", len(sources), len(combined.Sources))
	}
}

func TestCombinerDict_GetItem(t *testing.T) {
	_, combined := makeCombinerDict()

	// A: 10 * 2 + 1 = 21
	val, ok := combined.Get("A")
	if !ok || val != 21 {
		t.Errorf("expected A=21, got %d (ok=%v)", val, ok)
	}

	// B: only in second source, so just 3
	val, ok = combined.Get("B")
	if !ok || val != 3 {
		t.Errorf("expected B=3, got %d (ok=%v)", val, ok)
	}

	// C: missing
	_, ok = combined.Get("C")
	if ok {
		t.Error("expected C to be missing")
	}
}

func TestCombinerDict_MustGet(t *testing.T) {
	_, combined := makeCombinerDict()

	if v := combined.MustGet("A"); v != 21 {
		t.Errorf("expected A=21, got %d", v)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected MustGet to panic for missing key")
		}
	}()
	combined.MustGet("C")
}

func TestCombinerDict_GetOrDefault(t *testing.T) {
	_, combined := makeCombinerDict()

	if v := combined.GetOrDefault("A", 0); v != 21 {
		t.Errorf("expected 21, got %d", v)
	}
	if v := combined.GetOrDefault("B", 0); v != 3 {
		t.Errorf("expected 3, got %d", v)
	}
	if v := combined.GetOrDefault("C", 42); v != 42 {
		t.Errorf("expected 42, got %d", v)
	}
}

func TestCombinerDict_Keys(t *testing.T) {
	_, combined := makeCombinerDict()
	keys := combined.Keys()
	sort.Strings(keys)
	if len(keys) != 2 || keys[0] != "A" || keys[1] != "B" {
		t.Errorf("expected [A B], got %v", keys)
	}
}

func TestCombinerDict_Items(t *testing.T) {
	_, combined := makeCombinerDict()
	items := combined.Items()
	itemMap := make(map[string]int)
	for _, item := range items {
		itemMap[item.Key] = item.Value
	}
	if itemMap["A"] != 21 {
		t.Errorf("expected A=21, got %d", itemMap["A"])
	}
	if itemMap["B"] != 3 {
		t.Errorf("expected B=3, got %d", itemMap["B"])
	}
	if len(items) != 2 {
		t.Errorf("expected 2 items, got %d", len(items))
	}
}

func TestStringSetUnion(t *testing.T) {
	a := NewStringSet([]string{"a", "b"})
	b := NewStringSet([]string{"b", "c"})
	result := StringSetUnion(a, b)
	assertStringSet(t, result, []string{"a", "b", "c"})
}

func TestCacheStateCombiner_Dicts(t *testing.T) {
	states := map[string]*WhoisCacheState{
		"x": NewWhoisCacheState(),
		"y": NewWhoisCacheState(),
		"z": NewWhoisCacheState(),
	}
	combined := NewCacheStateCombiner(states)

	// Verify sources are the original maps
	for _, prop := range []string{"macros", "prefix4", "prefix6"} {
		var combinerSources []map[string]StringSet
		switch prop {
		case "macros":
			combinerSources = combined.Macros.Sources
		case "prefix4":
			combinerSources = combined.Prefix4.Sources
		case "prefix6":
			combinerSources = combined.Prefix6.Sources
		}
		if len(combinerSources) != 3 {
			t.Errorf("%s: expected 3 sources, got %d", prop, len(combinerSources))
		}
	}
}

func TestCacheStateCombiner_Serial(t *testing.T) {
	states := map[string]*WhoisCacheState{
		"x": NewWhoisCacheState(),
		"y": NewWhoisCacheState(),
		"z": NewWhoisCacheState(),
	}
	// Set serials matching Python test: ord('x')=120, ord('y')=121, ord('z')=122
	states["x"].Serial = "120"
	states["y"].Serial = "121"
	states["z"].Serial = "122"

	combined := NewCacheStateCombiner(states)
	expected := "x:120,y:121,z:122"
	if combined.Serial != expected {
		t.Errorf("expected serial %q, got %q", expected, combined.Serial)
	}
}
