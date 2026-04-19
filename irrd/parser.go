package irrd

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	reStripComment = regexp.MustCompile(`\s*#.*`)
	reHeader       = regexp.MustCompile(`%START Version: (\d+) ([\w-]+) (\d+)-(\d+)`)
	reRange        = regexp.MustCompile(`.*?(\d+)\W?-\W?(\d+).*`)
	reInvalidRange = regexp.MustCompile(`.*ERROR.*(I|i)nvalid range.*`)
	reDontExist    = regexp.MustCompile(`.*ERROR.*serials.*don.t exist.*`)
)

// Header represents parsed IRRD stream header information.
type Header struct {
	Version int
	Source  string
	Serials [2]int
}

// ParseHeader extracts header data from a %START line.
// Returns nil if the line does not match the expected format.
func ParseHeader(line string) *Header {
	match := reHeader.FindStringSubmatch(line)
	if match == nil {
		return nil
	}
	version, _ := strconv.Atoi(match[1])
	start, _ := strconv.Atoi(match[3])
	end, _ := strconv.Atoi(match[4])
	return &Header{
		Version: version,
		Source:  match[2],
		Serials: [2]int{start, end},
	}
}

// ParseRecord parses a block of lines into a Record by dispatching on the first key.
func ParseRecord(block []string) (Record, error) {
	if len(block) == 0 {
		return nil, &ParseFailure{Message: "empty block"}
	}
	key := strings.SplitN(block[0], ":", 2)[0]
	key = strings.ToLower(strings.TrimSpace(key))

	switch key {
	case "as-set":
		return parseMacro(block)
	case "route":
		return parseRoute(block)
	case "route6":
		return parseRoute6(block)
	default:
		return Unrecognised{Key: key}, nil
	}
}

func parseMacro(block []string) (Macro, error) {
	name, err := BlockLookup(block, "as-set")
	if err != nil {
		return Macro{}, err
	}
	name = strings.ToUpper(name)

	var members []string
	for _, line := range BlockLookupMany(block, "members") {
		items := strings.Split(line, ",")
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item != "" {
				members = append(members, strings.ToUpper(item))
			}
		}
	}
	return Macro{Name: name, Members: members}, nil
}

func parseRoute(block []string) (Route, error) {
	prefix, err := BlockLookup(block, "route")
	if err != nil {
		return Route{}, err
	}
	origin, err := BlockLookup(block, "origin")
	if err != nil {
		return Route{}, err
	}
	return Route{Prefix: prefix, Origin: strings.ToUpper(origin)}, nil
}

func parseRoute6(block []string) (Route6, error) {
	prefix, err := BlockLookup(block, "route6")
	if err != nil {
		return Route6{}, err
	}
	origin, err := BlockLookup(block, "origin")
	if err != nil {
		return Route6{}, err
	}
	return Route6{Prefix: prefix, Origin: strings.ToUpper(origin)}, nil
}

// BlockLookup finds a single value for a key in a block of lines.
// Comments (# ...) are stripped from the value.
func BlockLookup(block []string, key string) (string, error) {
	prefix := key + ":"
	for _, line := range block {
		if strings.HasPrefix(line, prefix) {
			val := strings.TrimSpace(line[len(prefix):])
			val = reStripComment.ReplaceAllString(val, "")
			return val, nil
		}
	}
	return "", fmt.Errorf("key not found: %s", key)
}

// BlockLookupMany finds all lines for a multiline value in a block.
// Continuation lines (lines without a colon that follow the key) are included.
func BlockLookupMany(block []string, key string) []string {
	var lines []string
	var curKey string
	for _, line := range block {
		val := strings.TrimSpace(line)
		if strings.HasPrefix(val, "#") {
			continue
		}
		if strings.Contains(val, ":") {
			parts := strings.SplitN(val, ":", 2)
			curKey = parts[0]
			val = parts[1]
		}
		if curKey == key {
			val = reStripComment.ReplaceAllString(val, "")
			lines = append(lines, val)
		}
	}
	return lines
}

// handleRangeException parses an error message for serial range bounds.
// Returns *SerialRangeError if bounds are found, *OutOfSyncError otherwise.
func handleRangeException(errorMsg string) error {
	match := reRange.FindStringSubmatch(errorMsg)
	if match == nil {
		return &OutOfSyncError{Message: errorMsg}
	}
	start, _ := strconv.Atoi(match[1])
	end, _ := strconv.Atoi(match[2])
	return &SerialRangeError{Message: errorMsg, First: start, Last: end}
}

// matchInvalidRangeError checks if a line matches known range error patterns.
// Returns an error if matched, nil otherwise.
func matchInvalidRangeError(line string) error {
	if reInvalidRange.MatchString(line) {
		return handleRangeException(line)
	}
	if reDontExist.MatchString(line) {
		return handleRangeException(line)
	}
	return nil
}

// handleError handles error lines from WHOIS responses.
func handleError(line string) error {
	tokens := strings.SplitN(line, ":", 4)
	if len(tokens) >= 2 {
		code, err := strconv.Atoi(strings.TrimSpace(tokens[1]))
		if err == nil && code == 401 {
			return handleRangeException(line)
		}
	}

	if err := matchInvalidRangeError(line); err != nil {
		return err
	}

	return &ErrorResponse{Message: line}
}
