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
