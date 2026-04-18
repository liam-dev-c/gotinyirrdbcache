package irrd

import (
	"fmt"
	"sort"
	"strings"
)

// KeyValue holds a key-value pair from a CombinerDict.
type KeyValue[V any] struct {
	Key   string
	Value V
}

// CombinerDict combines multiple maps by applying a reducer function
// to values that share the same key across sources.
type CombinerDict[V any] struct {
	Sources []map[string]V
	Reducer func(V, V) V
}

// NewCombinerDict creates a CombinerDict from a slice of source maps and a reducer.
func NewCombinerDict[V any](sources []map[string]V, reducer func(V, V) V) *CombinerDict[V] {
	return &CombinerDict[V]{
		Sources: sources,
		Reducer: reducer,
	}
}

// Get retrieves the combined value for a key. Returns false if the key is not found.
func (c *CombinerDict[V]) Get(key string) (V, bool) {
	var values []V
	for _, source := range c.Sources {
		if v, ok := source[key]; ok {
			values = append(values, v)
		}
	}
	if len(values) == 0 {
		var zero V
		return zero, false
	}
	result := values[0]
	for _, v := range values[1:] {
		result = c.Reducer(result, v)
	}
	return result, true
}

// MustGet retrieves the combined value for a key, panicking if not found.
func (c *CombinerDict[V]) MustGet(key string) V {
	v, ok := c.Get(key)
	if !ok {
		panic(fmt.Sprintf("key not found: %s", key))
	}
	return v
}

// GetOrDefault retrieves the combined value for a key, returning def if not found.
func (c *CombinerDict[V]) GetOrDefault(key string, def V) V {
	v, ok := c.Get(key)
	if !ok {
		return def
	}
	return v
}

// Keys returns the union of all keys across all sources.
func (c *CombinerDict[V]) Keys() []string {
	seen := make(map[string]struct{})
	for _, source := range c.Sources {
		for k := range source {
			seen[k] = struct{}{}
		}
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Items returns all key-value pairs with values combined via the reducer.
func (c *CombinerDict[V]) Items() []KeyValue[V] {
	keys := c.Keys()
	items := make([]KeyValue[V], 0, len(keys))
	for _, k := range keys {
		v, _ := c.Get(k)
		items = append(items, KeyValue[V]{Key: k, Value: v})
	}
	return items
}

// StringSetUnion combines two StringSets by union.
func StringSetUnion(a, b StringSet) StringSet {
	result := make(StringSet, len(a)+len(b))
	for k := range a {
		result[k] = struct{}{}
	}
	for k := range b {
		result[k] = struct{}{}
	}
	return result
}

// CacheStateCombiner provides a combined view of multiple WhoisCacheState instances.
type CacheStateCombiner struct {
	Macros    *CombinerDict[StringSet]
	Prefix4   *CombinerDict[StringSet]
	Prefix6   *CombinerDict[StringSet]
	Serial    string
	UpdatedAt string
}

// NewCacheStateCombiner creates a combiner from a map of named cache states.
// States are sorted by name for deterministic output.
func NewCacheStateCombiner(statesByName map[string]*WhoisCacheState) *CacheStateCombiner {
	names := make([]string, 0, len(statesByName))
	for name := range statesByName {
		names = append(names, name)
	}
	sort.Strings(names)

	macroSources := make([]map[string]StringSet, len(names))
	prefix4Sources := make([]map[string]StringSet, len(names))
	prefix6Sources := make([]map[string]StringSet, len(names))
	serialParts := make([]string, len(names))
	updatedParts := make([]string, len(names))

	for i, name := range names {
		st := statesByName[name]
		macroSources[i] = st.Macros
		prefix4Sources[i] = st.Prefix4
		prefix6Sources[i] = st.Prefix6
		serialParts[i] = fmt.Sprintf("%s:%s", name, st.Serial)
		updatedParts[i] = fmt.Sprintf("%s:%s", name, st.UpdatedAt)
	}

	return &CacheStateCombiner{
		Macros:    NewCombinerDict(macroSources, StringSetUnion),
		Prefix4:   NewCombinerDict(prefix4Sources, StringSetUnion),
		Prefix6:   NewCombinerDict(prefix6Sources, StringSetUnion),
		Serial:    strings.Join(serialParts, ","),
		UpdatedAt: strings.Join(updatedParts, ","),
	}
}
