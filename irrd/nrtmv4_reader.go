package irrd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
)

// ParseNRTMv4Snapshot parses an NRTMv4 snapshot file (JSON Text Sequences, RFC 7464).
// The first record is validated against the provided source, sessionID and version.
func ParseNRTMv4Snapshot(r io.Reader, source, sessionID string, version int) ([]Record, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // up to 10MB per line

	var records []Record
	first := true
	total := 0
	skipped := 0

	for scanner.Scan() {
		line := scanner.Text()
		// Strip RFC 7464 record separator (0x1E) prefix
		line = strings.TrimLeft(line, "\x1e")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if first {
			first = false
			var hdr NRTMv4FileHeader
			if err := json.Unmarshal([]byte(line), &hdr); err != nil {
				return nil, fmt.Errorf("parsing snapshot file header: %w", err)
			}
			if err := validateNRTMv4FileHeader(hdr, "snapshot", source, sessionID, version); err != nil {
				return nil, err
			}
			continue
		}

		total++

		var rec NRTMv4Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parsing NRTMv4 snapshot record: %w", err)
		}

		parsed, err := parseRPSLText(rec.RPSLText())
		if err != nil {
			skipped++
			continue // skip unparseable records
		}
		if _, ok := parsed.(Unrecognised); ok {
			skipped++
			continue
		}
		records = append(records, parsed)
	}

	log.Printf("NRTMv4: snapshot parsed %d records, kept %d, skipped %d", total, len(records), skipped)

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading NRTMv4 snapshot: %w", err)
	}

	return records, nil
}

// ParseNRTMv4Delta parses an NRTMv4 delta file (JSON Text Sequences, RFC 7464).
// Returns Update structs with actions mapped: "add_modify" → "ADD", "delete" → "DEL".
// The first record is validated against the provided source, sessionID and version.
func ParseNRTMv4Delta(r io.Reader, source, sessionID string, version int) ([]Update, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	var updates []Update
	first := true

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimLeft(line, "\x1e")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if first {
			first = false
			var hdr NRTMv4FileHeader
			if err := json.Unmarshal([]byte(line), &hdr); err != nil {
				return nil, fmt.Errorf("parsing delta file header: %w", err)
			}
			if err := validateNRTMv4FileHeader(hdr, "delta", source, sessionID, version); err != nil {
				return nil, err
			}
			continue
		}

		var rec NRTMv4Record
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parsing NRTMv4 delta record: %w", err)
		}

		action, err := mapNRTMv4Action(rec.Action)
		if err != nil {
			return nil, err
		}

		parsed, err := parseRPSLText(rec.RPSLText())
		if err != nil {
			continue // skip unparseable records
		}

		updates = append(updates, Update{
			Action: action,
			Record: parsed,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading NRTMv4 delta: %w", err)
	}

	return updates, nil
}

// mapNRTMv4Action converts NRTMv4 action strings to the internal ADD/DEL format.
func mapNRTMv4Action(action string) (string, error) {
	switch strings.ToLower(action) {
	case "add_modify":
		return "ADD", nil
	case "delete":
		return "DEL", nil
	default:
		return "", fmt.Errorf("unknown NRTMv4 action: %s", action)
	}
}

// validateNRTMv4FileHeader checks that the file header matches the expected values.
func validateNRTMv4FileHeader(h NRTMv4FileHeader, expectedType, source, sessionID string, version int) error {
	if h.NRTMVersion != 4 {
		return fmt.Errorf("NRTMv4 %s file header: nrtm_version %d, want 4", expectedType, h.NRTMVersion)
	}
	if h.Type != expectedType {
		return fmt.Errorf("NRTMv4 %s file header: type %q, want %q", expectedType, h.Type, expectedType)
	}
	if h.Source != source {
		return fmt.Errorf("NRTMv4 %s file header: source %q does not match expected %q", expectedType, h.Source, source)
	}
	if h.SessionID != sessionID {
		return fmt.Errorf("NRTMv4 %s file header: session_id %q does not match notification %q", expectedType, h.SessionID, sessionID)
	}
	if h.Version != version {
		return fmt.Errorf("NRTMv4 %s file header: version %d does not match notification %d", expectedType, h.Version, version)
	}
	return nil
}

// parseRPSLText splits an RPSL object_text into lines and parses it using ParseRecord.
func parseRPSLText(objectText string) (Record, error) {
	lines := strings.Split(strings.TrimSpace(objectText), "\n")
	var cleaned []string
	for _, l := range lines {
		l = strings.TrimRight(l, "\r")
		if l != "" {
			cleaned = append(cleaned, l)
		}
	}
	if len(cleaned) == 0 {
		return nil, fmt.Errorf("empty RPSL object")
	}
	return ParseRecord(cleaned)
}
