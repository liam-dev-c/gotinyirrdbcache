package irrd

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Update represents a single update from an IRRD update stream.
type Update struct {
	Action string // "ADD" or "DEL"
	Serial string
	Record Record
}

// ParseDump parses a full IRRD database dump, returning all records.
func ParseDump(r io.Reader) ([]Record, error) {
	br := bufio.NewReader(r)
	var records []Record
	for {
		rec, err := readAndParseRecord(br)
		if err != nil {
			return nil, err
		}
		if rec == nil {
			break
		}
		records = append(records, rec)
	}
	return records, nil
}

// ParseUpdates parses an IRRD update stream, returning all updates.
func ParseUpdates(r io.Reader) ([]Update, error) {
	br := bufio.NewReader(r)
	header, err := readHeader(br)
	if err != nil {
		return nil, err
	}
	if header == nil {
		return nil, nil
	}

	currentSerial := header.Serials[0]
	var updates []Update

	for {
		action, serial, err := readActSerial(br, strconv.Itoa(currentSerial))
		if err != nil {
			return nil, err
		}
		if action == "" {
			break
		}

		rec, err := readAndParseRecord(br)
		if err != nil {
			return nil, err
		}

		updates = append(updates, Update{
			Action: action,
			Serial: serial,
			Record: rec,
		})
		currentSerial++
	}
	return updates, nil
}

// ReadHeader reads and parses a header from an io.Reader.
// This is the public API that wraps the reader in a bufio.Reader.
func ReadHeader(r io.Reader) (*Header, error) {
	br := bufio.NewReader(r)
	return readHeader(br)
}

// readHeader reads the START header from a buffered reader.
// It looks for %START or %ERROR within the first 6 lines.
func readHeader(br *bufio.Reader) (*Header, error) {
	watchdog := 6
	for watchdog > 0 {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}
		if err == io.EOF && line == "" {
			break
		}
		watchdog--

		line = strings.TrimRight(line, "\n\r")

		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "%END") {
			break
		}
		if strings.HasPrefix(line, "%START") {
			return ParseHeader(line), nil
		}
		if strings.HasPrefix(line, "% ERROR") || strings.HasPrefix(line, "%ERROR") {
			return nil, handleError(line)
		}

		if err == io.EOF {
			break
		}
	}
	return nil, nil
}

// readRecord reads a block of lines (a single record) from the reader.
// Records are separated by blank lines. Comment lines (starting with #) are skipped.
func readRecord(br *bufio.Reader) ([]string, error) {
	var block []string
	for {
		line, err := br.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		if line == "\n" || line == "\r\n" {
			if len(block) > 0 {
				break
			}
			continue
		}

		if err == io.EOF {
			// Handle last line without newline
			if line != "" && !strings.HasPrefix(line, "#") {
				block = append(block, strings.TrimRight(line, "\n\r"))
			}
			break
		}

		line = strings.TrimRight(line, "\n\r")
		if line != "" && !strings.HasPrefix(line, "#") {
			block = append(block, line)
		}
	}
	if len(block) == 0 {
		return nil, nil
	}
	return block, nil
}

// readAndParseRecord reads a record block and parses it into a Record.
func readAndParseRecord(br *bufio.Reader) (Record, error) {
	block, err := readRecord(br)
	if err != nil {
		return nil, err
	}
	if block == nil {
		return nil, nil
	}
	return ParseRecord(block)
}

// readActSerial reads an ADD or DEL action line with its serial.
// If the action line doesn't include a serial, the fallbackSerial is used.
func readActSerial(br *bufio.Reader, fallbackSerial string) (action string, serial string, err error) {
	for {
		line, readErr := br.ReadString('\n')
		if readErr != nil && readErr != io.EOF {
			return "", "", readErr
		}

		if readErr == io.EOF && line == "" {
			return "", "", nil
		}

		line = strings.TrimRight(line, "\n\r")

		if line == "" {
			if readErr == io.EOF {
				return "", "", nil
			}
			continue
		}

		first := line[0]
		if first == '%' || first == '#' {
			if strings.Contains(strings.ToLower(line), "error") {
				return "", "", &ErrorResponse{Message: line}
			}
			if readErr == io.EOF {
				return "", "", nil
			}
			continue
		}

		if strings.HasPrefix(line, "ADD") {
			s := parseActSerial(line, fallbackSerial)
			return "ADD", s, nil
		}
		if strings.HasPrefix(line, "DEL") {
			s := parseActSerial(line, fallbackSerial)
			return "DEL", s, nil
		}

		return "", "", &ParseFailure{Message: fmt.Sprintf("Cannot parse: %s", line)}
	}
}

// parseActSerial extracts the serial from an action line (e.g., "ADD 2393925").
// If no serial is present, falls back to the provided default.
func parseActSerial(line string, fallbackSerial string) string {
	serial := strings.TrimSpace(line[3:])
	if serial == "" && fallbackSerial != "" {
		return fallbackSerial
	}
	return serial
}
