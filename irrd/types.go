package irrd

// Record is the interface all parsed record types implement.
// The unexported method seals the interface to this package.
type Record interface {
	recordType() string
}

// Macro represents an AS-SET with its members.
type Macro struct {
	Name    string
	Members []string
}

func (m Macro) recordType() string { return "macro" }

// Route represents an IPv4 route prefix and its origin ASN.
type Route struct {
	Prefix string
	Origin string
}

func (r Route) recordType() string { return "route" }

// Route6 represents an IPv6 route prefix and its origin ASN.
type Route6 struct {
	Prefix string
	Origin string
}

func (r Route6) recordType() string { return "route6" }

// Unrecognised represents a record type that is not handled.
type Unrecognised struct {
	Key string
}

func (u Unrecognised) recordType() string { return "unrecognised" }
