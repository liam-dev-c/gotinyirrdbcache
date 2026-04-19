package irrd

// NotificationFile represents the parsed content of an NRTMv4 Update Notification File.
type NotificationFile struct {
	NRTMVersion    int         `json:"nrtm_version"`
	Type           string      `json:"type"`
	Source         string      `json:"source"`
	SessionID      string      `json:"session_id"`
	Version        int         `json:"version"`
	Timestamp      string      `json:"timestamp"`
	Snapshot       SnapshotRef `json:"snapshot"`
	Deltas         []DeltaRef  `json:"deltas"`
	NextSigningKey string      `json:"next_signing_key,omitempty"`
}

// SnapshotRef is a reference to a snapshot file in the notification.
type SnapshotRef struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
	Hash    string `json:"hash"` // SHA-256, hex-encoded
}

// DeltaRef is a reference to a delta file in the notification.
type DeltaRef struct {
	Version int    `json:"version"`
	URL     string `json:"url"`
	Hash    string `json:"hash"` // SHA-256, hex-encoded
}

// NRTMv4FileHeader is the first record in an NRTMv4 snapshot or delta file.
type NRTMv4FileHeader struct {
	NRTMVersion int    `json:"nrtm_version"`
	Type        string `json:"type"`
	Source      string `json:"source"`
	SessionID   string `json:"session_id"`
	Version     int    `json:"version"`
}

// NRTMv4Record represents a single record in an NRTMv4 snapshot or delta file.
// For add_modify records the RPSL text is in "object" (IRRD) or "object_text" (RFC draft).
// For delete records, "object_class" and "primary_key" are used instead.
type NRTMv4Record struct {
	Action      string `json:"action"`       // "add_modify" or "delete" (delta); absent in snapshot
	Object      string `json:"object"`       // RPSL object as text (IRRD/RIPE format)
	ObjectText  string `json:"object_text"`  // RPSL object as text (RFC draft format)
	ObjectClass string `json:"object_class"` // for delete: object class (e.g. "route")
	PrimaryKey  string `json:"primary_key"`  // for delete: RPSL primary key (e.g. "192.0.2.0/24AS65001")
}

// RPSLText returns the RPSL object text from whichever field is populated.
func (r NRTMv4Record) RPSLText() string {
	if r.Object != "" {
		return r.Object
	}
	return r.ObjectText
}
