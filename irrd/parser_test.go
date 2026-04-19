package irrd

import (
	"errors"
	"testing"
)

func TestBlockLookup(t *testing.T) {
	block := []string{
		"route:         167.96.0.0/16",
		"descr:         Cyprus Minerals Company",
		"origin:        AS2900",
		"mnt-by:        MAINT-AS2900",
	}
	val, err := BlockLookup(block, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if val != "AS2900" {
		t.Errorf("expected AS2900, got %s", val)
	}

	_, err = BlockLookup(block, "nonexistent")
	if err == nil {
		t.Error("expected error for missing key")
	}
}

func TestBlockLookupStripComment(t *testing.T) {
	block := []string{
		"origin:         as12726   # haha gotcha",
	}
	val, err := BlockLookup(block, "origin")
	if err != nil {
		t.Fatal(err)
	}
	if val != "as12726" {
		t.Errorf("expected as12726, got %q", val)
	}
}

func TestBlockLookupMany(t *testing.T) {
	block := []string{
		"as-set:        AS-OREGON-IX-PEERAGE",
		"descr:         Peerage from the OREGON Exchange",
		"members:       AS4201, AS1798, AS3582, AS4222, AS2914,",
		"               AS6447, AS5650, AS6108, AS3838, AS1982,",
		"               AS4534, AS5798, AS8028",
		"tech-c:        DMM65",
	}
	lines := BlockLookupMany(block, "members")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(lines), lines)
	}
}

func TestParseRecord_Macro(t *testing.T) {
	block := []string{
		"as-set:        AS-LEN",
		"descr:         Lane Education Network Clients",
		"members:       AS4222, AS4016, AS4529, AS6377",
		"tech-c:        DMM65",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := rec.(Macro)
	if !ok {
		t.Fatalf("expected Macro, got %T", rec)
	}
	if m.Name != "AS-LEN" {
		t.Errorf("expected name AS-LEN, got %s", m.Name)
	}
	expected := []string{"AS4222", "AS4016", "AS4529", "AS6377"}
	if len(m.Members) != len(expected) {
		t.Fatalf("expected %d members, got %d", len(expected), len(m.Members))
	}
	for i, e := range expected {
		if m.Members[i] != e {
			t.Errorf("member[%d]: expected %s, got %s", i, e, m.Members[i])
		}
	}
}

func TestParseRecord_Route(t *testing.T) {
	block := []string{
		"route:         167.96.0.0/16",
		"descr:         Cyprus Minerals Company",
		"origin:        AS2900",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rec.(Route)
	if !ok {
		t.Fatalf("expected Route, got %T", rec)
	}
	if r.Prefix != "167.96.0.0/16" || r.Origin != "AS2900" {
		t.Errorf("unexpected route: %+v", r)
	}
}

func TestParseRecord_Route6(t *testing.T) {
	block := []string{
		"route6:     2001:1988::/32",
		"descr:      NextWeb: IPv6",
		"origin:     AS16467",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := rec.(Route6)
	if !ok {
		t.Fatalf("expected Route6, got %T", rec)
	}
	if r.Prefix != "2001:1988::/32" || r.Origin != "AS16467" {
		t.Errorf("unexpected route6: %+v", r)
	}
}

func TestParseRecord_Unrecognised(t *testing.T) {
	block := []string{
		"mntner:        MAINT-AS6293",
		"descr:         Maintainer for AS 6293",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	u, ok := rec.(Unrecognised)
	if !ok {
		t.Fatalf("expected Unrecognised, got %T", rec)
	}
	if u.Key != "mntner" {
		t.Errorf("expected key mntner, got %s", u.Key)
	}
}

func TestParseMacro_CaseNormalization(t *testing.T) {
	block := []string{
		"as-set:         as-tmpebonecwix",
		"members:        as3727, as4445, AS4610",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	m := rec.(Macro)
	if m.Name != "AS-TMPEBONECWIX" {
		t.Errorf("expected uppercased name, got %s", m.Name)
	}
	if m.Members[0] != "AS3727" || m.Members[1] != "AS4445" {
		t.Errorf("expected uppercased members, got %v", m.Members)
	}
}

func TestParseRoute_OriginCaseNormalization(t *testing.T) {
	block := []string{
		"route:          193.254.30.0/24",
		"origin:         as12726   # haha gotcha",
	}
	rec, err := ParseRecord(block)
	if err != nil {
		t.Fatal(err)
	}
	r := rec.(Route)
	if r.Origin != "AS12726" {
		t.Errorf("expected AS12726, got %s", r.Origin)
	}
}

func TestParseHeader(t *testing.T) {
	h := ParseHeader("%START Version: 3 radb 2393925-2393950")
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if h.Version != 3 {
		t.Errorf("expected version 3, got %d", h.Version)
	}
	if h.Source != "radb" {
		t.Errorf("expected source radb, got %s", h.Source)
	}
	if h.Serials[0] != 2393925 || h.Serials[1] != 2393950 {
		t.Errorf("unexpected serials: %v", h.Serials)
	}
}

func TestParseHeader_Invalid(t *testing.T) {
	h := ParseHeader("some random line")
	if h != nil {
		t.Errorf("expected nil for invalid header, got %+v", h)
	}
}

func TestParseHeader_HyphenatedSource(t *testing.T) {
	h := ParseHeader("%START Version: 3 RIPE-NONAUTH 12345-67890")
	if h == nil {
		t.Fatal("expected non-nil header for hyphenated source name")
	}
	if h.Source != "RIPE-NONAUTH" {
		t.Errorf("expected source RIPE-NONAUTH, got %s", h.Source)
	}
	if h.Serials[0] != 12345 || h.Serials[1] != 67890 {
		t.Errorf("unexpected serials: %v", h.Serials)
	}
}

func TestParseHeader_Filtered(t *testing.T) {
	h := ParseHeader("%START Version: 3 ARIN 66038-66844 FILTERED")
	if h == nil {
		t.Fatal("expected non-nil header")
	}
	if h.Version != 3 || h.Source != "ARIN" {
		t.Errorf("unexpected header: %+v", h)
	}
	if h.Serials[0] != 66038 || h.Serials[1] != 66844 {
		t.Errorf("unexpected serials: %v", h.Serials)
	}
}

func TestHandleRangeException_WithRange(t *testing.T) {
	err := handleRangeException("%ERROR:401: invalid range: Not within 2278326-38325450")
	var sre *SerialRangeError
	if !errors.As(err, &sre) {
		t.Fatalf("expected SerialRangeError, got %T", err)
	}
	if sre.First != 2278326 || sre.Last != 38325450 {
		t.Errorf("expected 2278326-38325450, got %d-%d", sre.First, sre.Last)
	}
}

func TestHandleRangeException_NoRange(t *testing.T) {
	err := handleRangeException("some error without range info")
	var oose *OutOfSyncError
	if !errors.As(err, &oose) {
		t.Fatalf("expected OutOfSyncError, got %T", err)
	}
}

func TestHandleError_Code401(t *testing.T) {
	err := handleError("%ERROR:401: invalid range: Not within 2278326-38325450")
	var sre *SerialRangeError
	if !errors.As(err, &sre) {
		t.Fatalf("expected SerialRangeError, got %T", err)
	}
}

func TestHandleError_RegexFallback(t *testing.T) {
	err := handleError("% ERROR: 4: Invalid range: serial(s) 789-765562 don't exist ")
	var sre *SerialRangeError
	if !errors.As(err, &sre) {
		t.Fatalf("expected SerialRangeError, got %T", err)
	}
	if sre.First != 789 || sre.Last != 765562 {
		t.Errorf("expected 789-765562, got %d-%d", sre.First, sre.Last)
	}
}

func TestHandleError_GeneralError(t *testing.T) {
	err := handleError("%ERROR")
	var er *ErrorResponse
	if !errors.As(err, &er) {
		t.Fatalf("expected ErrorResponse, got %T", err)
	}
}

func TestParseRecord_EmptyBlock(t *testing.T) {
	_, err := ParseRecord([]string{})
	if err == nil {
		t.Fatal("expected error for empty block")
	}
	var pf *ParseFailure
	if !errors.As(err, &pf) {
		t.Fatalf("expected ParseFailure, got %T", err)
	}
}

func TestParseRecord_Route_MissingOrigin(t *testing.T) {
	block := []string{"route:  1.2.3.0/24"}
	_, err := ParseRecord(block)
	if err == nil {
		t.Fatal("expected error for route missing origin")
	}
}

func TestParseRecord_Route6_MissingOrigin(t *testing.T) {
	block := []string{"route6:  2001:db8::/32"}
	_, err := ParseRecord(block)
	if err == nil {
		t.Fatal("expected error for route6 missing origin")
	}
}

func TestParseMacro_MissingASSet(t *testing.T) {
	_, err := parseMacro([]string{"descr: no as-set key here"})
	if err == nil {
		t.Fatal("expected error for missing as-set key")
	}
}

func TestParseRoute_MissingRouteKey(t *testing.T) {
	_, err := parseRoute([]string{"descr: no route key here"})
	if err == nil {
		t.Fatal("expected error for missing route key")
	}
}

func TestParseRoute6_MissingRoute6Key(t *testing.T) {
	_, err := parseRoute6([]string{"descr: no route6 key here"})
	if err == nil {
		t.Fatal("expected error for missing route6 key")
	}
}

func TestBlockLookupMany_CommentLine(t *testing.T) {
	block := []string{
		"members: AS1, AS2,",
		"# this is a comment",
		"         AS3",
	}
	lines := BlockLookupMany(block, "members")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (comment skipped), got %d: %v", len(lines), lines)
	}
}
