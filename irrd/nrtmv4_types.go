package irrd

// NotificationFile represents the parsed content of an NRTMv4 Update Notification File.
type NotificationFile struct {
	NRTMVersion int         `json:"nrtm_version"`
	Type        string      `json:"type"`
	Source      string      `json:"source"`
	SessionID   string      `json:"session_id"`
	Version     int         `json:"version"`
	Timestamp   string      `json:"timestamp"`
	Snapshot    SnapshotRef `json:"snapshot"`
	Deltas      []DeltaRef  `json:"deltas"`
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
// The RPSL text may appear as "object" (RIPE implementation) or "object_text" (RFC draft).
type NRTMv4Record struct {
	Action     string `json:"action"`      // "add" (snapshot), "add_modify" or "delete" (delta)
	Object     string `json:"object"`      // RPSL object as text (RIPE format)
	ObjectText string `json:"object_text"` // RPSL object as text (RFC draft format)
}

// RPSLText returns the RPSL object text from whichever field is populated.
func (r NRTMv4Record) RPSLText() string {
	if r.Object != "" {
		return r.Object
	}
	return r.ObjectText
}
