package irrd

import "time"

// StringSet is a set of strings backed by a map.
type StringSet map[string]struct{}

// NewStringSet creates a StringSet from a slice of strings.
func NewStringSet(items []string) StringSet {
	s := make(StringSet, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// Add adds a value to the set.
func (s StringSet) Add(val string) {
	s[val] = struct{}{}
}

// Remove removes a value from the set.
func (s StringSet) Remove(val string) {
	delete(s, val)
}

// Contains returns true if the set contains the value.
func (s StringSet) Contains(val string) bool {
	_, ok := s[val]
	return ok
}

// Slice returns the set contents as a slice.
func (s StringSet) Slice() []string {
	result := make([]string, 0, len(s))
	for k := range s {
		result = append(result, k)
	}
	return result
}

// WhoisCacheState holds the in-memory state for one IRRD cache.
type WhoisCacheState struct {
	Serial    string
	Macros    map[string]StringSet
	Prefix4   map[string]StringSet
	Prefix6   map[string]StringSet
	UpdatedAt time.Time
}

// NewWhoisCacheState creates an empty cache state.
func NewWhoisCacheState() *WhoisCacheState {
	return &WhoisCacheState{
		Macros:  make(map[string]StringSet),
		Prefix4: make(map[string]StringSet),
		Prefix6: make(map[string]StringSet),
	}
}

// ApplyUpdate applies a single update to the cache state.
func (s *WhoisCacheState) ApplyUpdate(u Update) {
	switch rec := u.Record.(type) {
	case Macro:
		s.updateMacro(u.Action, rec)
	case Route:
		s.updateRoute(u.Action, rec)
	case Route6:
		s.updateRoute6(u.Action, rec)
	case Unrecognised:
		// no-op
	}
	s.Serial = u.Serial
	s.UpdatedAt = time.Now()
}

func (s *WhoisCacheState) updateMacro(action string, m Macro) {
	if action == "ADD" {
		s.Macros[m.Name] = NewStringSet(m.Members)
	} else if action == "DEL" {
		delete(s.Macros, m.Name)
	}
}

func (s *WhoisCacheState) updateRoute(action string, r Route) {
	if action == "ADD" {
		if _, ok := s.Prefix4[r.Origin]; !ok {
			s.Prefix4[r.Origin] = make(StringSet)
		}
		s.Prefix4[r.Origin].Add(r.Prefix)
	} else if action == "DEL" {
		if prefixes, ok := s.Prefix4[r.Origin]; ok {
			prefixes.Remove(r.Prefix)
			if len(prefixes) == 0 {
				delete(s.Prefix4, r.Origin)
			}
		}
	}
}

func (s *WhoisCacheState) updateRoute6(action string, r Route6) {
	if action == "ADD" {
		if _, ok := s.Prefix6[r.Origin]; !ok {
			s.Prefix6[r.Origin] = make(StringSet)
		}
		s.Prefix6[r.Origin].Add(r.Prefix)
	} else if action == "DEL" {
		if prefixes, ok := s.Prefix6[r.Origin]; ok {
			prefixes.Remove(r.Prefix)
			if len(prefixes) == 0 {
				delete(s.Prefix6, r.Origin)
			}
		}
	}
}
