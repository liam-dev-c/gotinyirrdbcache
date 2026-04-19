package irrd

import (
	"os"
	"strings"
	"testing"
)

func TestParseNRTMv4Snapshot_FromFile(t *testing.T) {
	f, err := os.Open("testdata/nrtmv4.snapshot.sample")
	if err != nil {
		t.Fatalf("opening sample: %v", err)
	}
	defer f.Close()

	records, err := ParseNRTMv4Snapshot(f, "RIPE", "db44e038-1f07-4d54-a307-1b32339f141a", 734256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// mntner is Unrecognised and skipped; expect route, route6, as-set
	if len(records) != 3 {
		t.Fatalf("got %d records, want 3", len(records))
	}

	route, ok := records[0].(Route)
	if !ok {
		t.Fatalf("record 0: expected Route, got %T", records[0])
	}
	if route.Prefix != "192.0.2.0/24" {
		t.Errorf("route prefix = %q, want 192.0.2.0/24", route.Prefix)
	}
	if route.Origin != "AS65001" {
		t.Errorf("route origin = %q, want AS65001", route.Origin)
	}

	route6, ok := records[1].(Route6)
	if !ok {
		t.Fatalf("record 1: expected Route6, got %T", records[1])
	}
	if route6.Prefix != "2001:db8::/32" {
		t.Errorf("route6 prefix = %q, want 2001:db8::/32", route6.Prefix)
	}

	macro, ok := records[2].(Macro)
	if !ok {
		t.Fatalf("record 2: expected Macro, got %T", records[2])
	}
	if macro.Name != "AS-EXAMPLE" {
		t.Errorf("macro name = %q, want AS-EXAMPLE", macro.Name)
	}
	if len(macro.Members) != 2 {
		t.Errorf("macro members = %d, want 2", len(macro.Members))
	}
}

func TestParseNRTMv4Delta_FromFile(t *testing.T) {
	f, err := os.Open("testdata/nrtmv4.delta.sample")
	if err != nil {
		t.Fatalf("opening sample: %v", err)
	}
	defer f.Close()

	updates, err := ParseNRTMv4Delta(f, "RIPE", "db44e038-1f07-4d54-a307-1b32339f141a", 734257)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(updates) != 2 {
		t.Fatalf("got %d updates, want 2", len(updates))
	}

	if updates[0].Action != "ADD" {
		t.Errorf("update 0 action = %q, want ADD", updates[0].Action)
	}
	route, ok := updates[0].Record.(Route)
	if !ok {
		t.Fatalf("update 0: expected Route, got %T", updates[0].Record)
	}
	if route.Prefix != "198.51.100.0/24" {
		t.Errorf("prefix = %q, want 198.51.100.0/24", route.Prefix)
	}

	if updates[1].Action != "DEL" {
		t.Errorf("update 1 action = %q, want DEL", updates[1].Action)
	}
	delRoute, ok := updates[1].Record.(Route)
	if !ok {
		t.Fatalf("update 1: expected Route, got %T", updates[1].Record)
	}
	if delRoute.Prefix != "192.0.2.0/24" {
		t.Errorf("delete prefix = %q, want 192.0.2.0/24", delRoute.Prefix)
	}
	if delRoute.Origin != "AS65001" {
		t.Errorf("delete origin = %q, want AS65001", delRoute.Origin)
	}
}

// TestParseNRTMv4Snapshot_ObjectTextField verifies "object_text" (RFC draft) field also works.
func TestParseNRTMv4Snapshot_ObjectTextField(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n" +
		`{"object_text":"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"}` + "\n"

	records, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if _, ok := records[0].(Route); !ok {
		t.Fatalf("expected Route, got %T", records[0])
	}
}

// TestParseNRTMv4Snapshot_RFC7464 verifies 0x1E record separator is handled.
func TestParseNRTMv4Snapshot_RFC7464(t *testing.T) {
	data := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n" +
		"\x1e" + `{"object_text":"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"}` + "\n"

	records, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
}

func TestParseNRTMv4Delta_InvalidAction(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"unknown","object_class":"route","primary_key":"10.0.0.0/8AS1"}` + "\n"

	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for unknown action")
	}
}

func TestParseNRTMv4Snapshot_InvalidJSON(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n" +
		`{not valid json}` + "\n"

	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for invalid JSON record")
	}
}

func TestParseNRTMv4Snapshot_EmptyRPSL(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n" +
		`{"object_text":""}` + "\n"

	records, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty RPSL is skipped (parseRPSLText returns error, record is skipped)
	if len(records) != 0 {
		t.Errorf("expected 0 records for empty RPSL, got %d", len(records))
	}
}

func TestParseNRTMv4Delta_InvalidJSON(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{not valid json}` + "\n"

	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for invalid JSON record")
	}
}

func TestParseNRTMv4Delta_SkipUnparseable(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"add_modify","object_text":""}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty RPSL is skipped
	if len(updates) != 0 {
		t.Errorf("expected 0 updates, got %d", len(updates))
	}
}

func TestParseNRTMv4Snapshot_SkipUnrecognised(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n" +
		`{"object_text":"mntner: MAINT-AS1\ndescr: test maintainer\n"}` + "\n" +
		`{"object_text":"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"}` + "\n"

	records, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record (mntner skipped), got %d", len(records))
	}
	if _, ok := records[0].(Route); !ok {
		t.Fatalf("expected Route, got %T", records[0])
	}
}

func TestParseNRTMv4Delta_DeleteRoute(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"delete","object_class":"route","primary_key":"192.0.2.0/24AS65001"}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 1 {
		t.Fatalf("got %d updates, want 1", len(updates))
	}
	if updates[0].Action != "DEL" {
		t.Errorf("action = %q, want DEL", updates[0].Action)
	}
	r, ok := updates[0].Record.(Route)
	if !ok {
		t.Fatalf("expected Route, got %T", updates[0].Record)
	}
	if r.Prefix != "192.0.2.0/24" || r.Origin != "AS65001" {
		t.Errorf("got prefix=%q origin=%q, want 192.0.2.0/24 AS65001", r.Prefix, r.Origin)
	}
}

func TestParseNRTMv4Delta_DeleteRoute6(t *testing.T) {
	// Primary key uses lowercase hex as IRRD sends it; prefix case must be preserved.
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"delete","object_class":"route6","primary_key":"2001:db8::/32AS65002"}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 1 || updates[0].Action != "DEL" {
		t.Fatalf("unexpected updates: %v", updates)
	}
	r, ok := updates[0].Record.(Route6)
	if !ok {
		t.Fatalf("expected Route6, got %T", updates[0].Record)
	}
	// Prefix must keep its original case; only origin is uppercased.
	if r.Prefix != "2001:db8::/32" || r.Origin != "AS65002" {
		t.Errorf("got prefix=%q origin=%q, want 2001:db8::/32 AS65002", r.Prefix, r.Origin)
	}
}

func TestParseNRTMv4Delta_DeleteMacro(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"delete","object_class":"as-set","primary_key":"AS-EXAMPLE"}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 1 || updates[0].Action != "DEL" {
		t.Fatalf("unexpected updates: %v", updates)
	}
	m, ok := updates[0].Record.(Macro)
	if !ok {
		t.Fatalf("expected Macro, got %T", updates[0].Record)
	}
	if m.Name != "AS-EXAMPLE" {
		t.Errorf("got name=%q, want AS-EXAMPLE", m.Name)
	}
}

func TestParseNRTMv4Delta_DeleteUnrecognisedClass(t *testing.T) {
	// Unrecognised object classes in deletes are skipped
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"delete","object_class":"mntner","primary_key":"TEST-MNT"}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 0 {
		t.Errorf("expected 0 updates (unrecognised class skipped), got %d", len(updates))
	}
}

func TestParseNRTMv4Delta_DeleteMissingFields(t *testing.T) {
	// Delete record with missing primary_key — should be skipped
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"delete","object_class":"route"}` + "\n"

	updates, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(updates) != 0 {
		t.Errorf("expected 0 updates (missing primary_key skipped), got %d", len(updates))
	}
}

func TestSplitRoutePrimaryKey(t *testing.T) {
	cases := []struct{ pk, wantPrefix, wantOrigin string }{
		{"192.0.2.0/24AS65001", "192.0.2.0/24", "AS65001"},
		{"2001:db8::/32AS65002", "2001:db8::/32", "AS65002"}, // lowercase IPv6 preserved
		{"10.0.0.0/8AS1", "10.0.0.0/8", "AS1"},
	}
	for _, tc := range cases {
		prefix, origin, err := splitRoutePrimaryKey(tc.pk)
		if err != nil {
			t.Errorf("splitRoutePrimaryKey(%q) error: %v", tc.pk, err)
			continue
		}
		if prefix != tc.wantPrefix || origin != tc.wantOrigin {
			t.Errorf("splitRoutePrimaryKey(%q) = %q, %q; want %q, %q", tc.pk, prefix, origin, tc.wantPrefix, tc.wantOrigin)
		}
	}
}

func TestSplitRoutePrimaryKey_Invalid(t *testing.T) {
	_, _, err := splitRoutePrimaryKey("no-as-number-here")
	if err == nil {
		t.Fatal("expected error for primary key without AS number")
	}
}

func TestParseNRTMv4Snapshot_WrongSource(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"OTHER","session_id":"s1","version":10}` + "\n"
	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for wrong source")
	}
}

func TestParseNRTMv4Snapshot_WrongSessionID(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"other","version":10}` + "\n"
	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for wrong session_id")
	}
}

func TestParseNRTMv4Snapshot_WrongVersion(t *testing.T) {
	data := `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"s1","version":99}` + "\n"
	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestParseNRTMv4Snapshot_WrongNRTMVersion(t *testing.T) {
	data := `{"nrtm_version":3,"type":"snapshot","source":"TEST","session_id":"s1","version":10}` + "\n"
	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for nrtm_version != 4")
	}
}

func TestParseNRTMv4Delta_WrongSource(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"OTHER","session_id":"s1","version":11}` + "\n"
	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for wrong source")
	}
}

func TestParseNRTMv4Delta_WrongSessionID(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"other","version":11}` + "\n"
	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for wrong session_id")
	}
}

func TestParseNRTMv4Delta_WrongVersion(t *testing.T) {
	data := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":99}` + "\n"
	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

func TestParseNRTMv4Snapshot_InvalidHeaderJSON(t *testing.T) {
	data := `{not valid json header}` + "\n"
	_, err := ParseNRTMv4Snapshot(strings.NewReader(data), "TEST", "s1", 10)
	if err == nil {
		t.Fatal("expected error for invalid header JSON")
	}
}

func TestParseNRTMv4Delta_InvalidHeaderJSON(t *testing.T) {
	data := `{not valid json header}` + "\n"
	_, err := ParseNRTMv4Delta(strings.NewReader(data), "TEST", "s1", 11)
	if err == nil {
		t.Fatal("expected error for invalid header JSON")
	}
}

func TestParseRPSLText_Empty(t *testing.T) {
	_, err := parseRPSLText("")
	if err == nil {
		t.Fatal("expected error for empty RPSL text")
	}
}

func TestParseRPSLText(t *testing.T) {
	text := "route: 203.0.113.0/24\norigin: AS65000\nsource: TEST\n"
	rec, err := parseRPSLText(text)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	route, ok := rec.(Route)
	if !ok {
		t.Fatalf("expected Route, got %T", rec)
	}
	if route.Prefix != "203.0.113.0/24" {
		t.Errorf("prefix = %q, want 203.0.113.0/24", route.Prefix)
	}
	if route.Origin != "AS65000" {
		t.Errorf("origin = %q, want AS65000", route.Origin)
	}
}
