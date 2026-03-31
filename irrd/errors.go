package irrd

// SerialRangeError indicates the requested update serial is out of range.
type SerialRangeError struct {
	Message string
	First   int
	Last    int
}

func (e *SerialRangeError) Error() string { return e.Message }

// OutOfSyncError indicates the cache is out of sync without serial range information.
type OutOfSyncError struct {
	Message string
}

func (e *OutOfSyncError) Error() string { return e.Message }

// ErrorResponse represents a general WHOIS error response.
type ErrorResponse struct {
	Message string
}

func (e *ErrorResponse) Error() string { return e.Message }

// ParseFailure indicates a failure to parse WHOIS data.
type ParseFailure struct {
	Message string
}

func (e *ParseFailure) Error() string { return e.Message }

// SessionResetError indicates the NRTMv4 session has changed, requiring a fresh snapshot.
type SessionResetError struct {
	OldSession string
	NewSession string
}

func (e *SessionResetError) Error() string {
	return "NRTMv4 session reset: " + e.OldSession + " -> " + e.NewSession
}

// HashMismatchError indicates a downloaded file's SHA-256 hash doesn't match expected.
type HashMismatchError struct {
	URL      string
	Expected string
	Actual   string
}

func (e *HashMismatchError) Error() string {
	return "hash mismatch for " + e.URL + ": expected " + e.Expected + ", got " + e.Actual
}

// SignatureError indicates JWS signature verification failed.
type SignatureError struct {
	Message string
}

func (e *SignatureError) Error() string { return e.Message }
