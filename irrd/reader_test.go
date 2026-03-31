package irrd

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func openTestdata(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseDump_RADB(t *testing.T) {
	f := openTestdata(t, "radb.db.sample")
	records, err := ParseDump(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 6 {
		t.Fatalf("expected 6 records, got %d", len(records))
	}

	// Record 0: Unrecognised(key='aut-num')
	if u, ok := records[0].(Unrecognised); !ok || u.Key != "aut-num" {
		t.Errorf("record 0: expected Unrecognised{aut-num}, got %+v", records[0])
	}

	// Record 1: Route(prefix='167.96.0.0/16', origin='AS2900')
	if r, ok := records[1].(Route); !ok || r.Prefix != "167.96.0.0/16" || r.Origin != "AS2900" {
		t.Errorf("record 1: expected Route{167.96.0.0/16, AS2900}, got %+v", records[1])
	}

	// Record 2: Unrecognised(key='mntner')
	if u, ok := records[2].(Unrecognised); !ok || u.Key != "mntner" {
		t.Errorf("record 2: expected Unrecognised{mntner}, got %+v", records[2])
	}

	// Record 3: Macro(name='AS-LEN', members=[AS4222, AS4016, AS4529, AS6377])
	if m, ok := records[3].(Macro); !ok || m.Name != "AS-LEN" {
		t.Errorf("record 3: expected Macro{AS-LEN}, got %+v", records[3])
	} else {
		expected := []string{"AS4222", "AS4016", "AS4529", "AS6377"}
		if len(m.Members) != len(expected) {
			t.Errorf("record 3: expected %d members, got %d", len(expected), len(m.Members))
		} else {
			for i, e := range expected {
				if m.Members[i] != e {
					t.Errorf("record 3 member[%d]: expected %s, got %s", i, e, m.Members[i])
				}
			}
		}
	}

	// Record 4: Macro(name='AS-OREGON-IX-PEERAGE', 13 members)
	if m, ok := records[4].(Macro); !ok || m.Name != "AS-OREGON-IX-PEERAGE" {
		t.Errorf("record 4: expected Macro{AS-OREGON-IX-PEERAGE}, got %+v", records[4])
	} else {
		expected := []string{"AS4201", "AS1798", "AS3582", "AS4222", "AS2914",
			"AS6447", "AS5650", "AS6108", "AS3838", "AS1982",
			"AS4534", "AS5798", "AS8028"}
		if len(m.Members) != len(expected) {
			t.Errorf("record 4: expected %d members, got %d: %v", len(expected), len(m.Members), m.Members)
		} else {
			for i, e := range expected {
				if m.Members[i] != e {
					t.Errorf("record 4 member[%d]: expected %s, got %s", i, e, m.Members[i])
				}
			}
		}
	}

	// Record 5: Route6(prefix='2001:1988::/32', origin='AS16467')
	if r, ok := records[5].(Route6); !ok || r.Prefix != "2001:1988::/32" || r.Origin != "AS16467" {
		t.Errorf("record 5: expected Route6{2001:1988::/32, AS16467}, got %+v", records[5])
	}
}

func TestParseDump_RIPE(t *testing.T) {
	f := openTestdata(t, "ripe.db.sample")
	records, err := ParseDump(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("expected 4 records, got %d", len(records))
	}

	// Record 0: Unrecognised(key='as-block')
	if u, ok := records[0].(Unrecognised); !ok || u.Key != "as-block" {
		t.Errorf("record 0: expected Unrecognised{as-block}, got %+v", records[0])
	}

	// Record 1: Macro(name='AS-TMPEBONECWIX', 24 members)
	if m, ok := records[1].(Macro); !ok || m.Name != "AS-TMPEBONECWIX" {
		t.Errorf("record 1: expected Macro{AS-TMPEBONECWIX}, got %+v", records[1])
	} else {
		expected := []string{"AS3727", "AS4445", "AS4610", "AS4624", "AS4637",
			"AS4654", "AS4655", "AS4656", "AS4659", "AS4681",
			"AS4696", "AS4714", "AS4849", "AS5089", "AS5090",
			"AS5532", "AS5551", "AS5559", "AS5655", "AS6081",
			"AS6255", "AS6292", "AS6618", "AS6639"}
		if len(m.Members) != len(expected) {
			t.Errorf("record 1: expected %d members, got %d: %v", len(expected), len(m.Members), m.Members)
		} else {
			for i, e := range expected {
				if m.Members[i] != e {
					t.Errorf("record 1 member[%d]: expected %s, got %s", i, e, m.Members[i])
				}
			}
		}
	}

	// Record 2: Route(prefix='193.254.30.0/24', origin='AS12726')
	if r, ok := records[2].(Route); !ok || r.Prefix != "193.254.30.0/24" || r.Origin != "AS12726" {
		t.Errorf("record 2: expected Route{193.254.30.0/24, AS12726}, got %+v", records[2])
	}

	// Record 3: Route6(prefix='2001:1578:200::/40', origin='AS12817')
	if r, ok := records[3].(Route6); !ok || r.Prefix != "2001:1578:200::/40" || r.Origin != "AS12817" {
		t.Errorf("record 3: expected Route6{2001:1578:200::/40, AS12817}, got %+v", records[3])
	}
}

func TestParseUpdates_RADB(t *testing.T) {
	f := openTestdata(t, "radb.updates.sample")
	updates, err := ParseUpdates(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d", len(updates))
	}

	// Update 0: ADD 2393925 Macro(AS-HURRICANE)
	u0 := updates[0]
	if u0.Action != "ADD" || u0.Serial != "2393925" {
		t.Errorf("update 0: expected ADD/2393925, got %s/%s", u0.Action, u0.Serial)
	}
	m, ok := u0.Record.(Macro)
	if !ok {
		t.Fatalf("update 0: expected Macro, got %T", u0.Record)
	}
	if m.Name != "AS-HURRICANE" {
		t.Errorf("update 0: expected AS-HURRICANE, got %s", m.Name)
	}
	expectedMembers := []string{"AS-LAIX", "AS-MEMSET", "AS-VOCUS", "AS-TPG",
		"AS-JAPAN-TELECOM", "AS4", "AS5", "AS10", "AS16", "AS17"}
	if len(m.Members) != len(expectedMembers) {
		t.Errorf("update 0: expected %d members, got %d: %v", len(expectedMembers), len(m.Members), m.Members)
	} else {
		for i, e := range expectedMembers {
			if m.Members[i] != e {
				t.Errorf("update 0 member[%d]: expected %s, got %s", i, e, m.Members[i])
			}
		}
	}

	// Update 1: DEL 2393926 Route(42.116.22.0/24, AS18403)
	u1 := updates[1]
	if u1.Action != "DEL" || u1.Serial != "2393926" {
		t.Errorf("update 1: expected DEL/2393926, got %s/%s", u1.Action, u1.Serial)
	}
	r, ok := u1.Record.(Route)
	if !ok {
		t.Fatalf("update 1: expected Route, got %T", u1.Record)
	}
	if r.Prefix != "42.116.22.0/24" || r.Origin != "AS18403" {
		t.Errorf("update 1: unexpected route %+v", r)
	}
}

func TestParseUpdates_L3(t *testing.T) {
	f := openTestdata(t, "l3.updates.sample")
	updates, err := ParseUpdates(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d", len(updates))
	}

	// Level3 doesn't provide serials in ADD/DEL lines, so fallback is used
	if updates[0].Action != "ADD" || updates[0].Serial != "767081" {
		t.Errorf("update 0: expected ADD/767081, got %s/%s", updates[0].Action, updates[0].Serial)
	}
	if updates[1].Action != "DEL" || updates[1].Serial != "767082" {
		t.Errorf("update 1: expected DEL/767082, got %s/%s", updates[1].Action, updates[1].Serial)
	}
}

func TestReadHeader_RADB(t *testing.T) {
	f := openTestdata(t, "radb.updates.sample")
	h, err := ReadHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 3 || h.Source != "radb" {
		t.Errorf("unexpected header: %+v", h)
	}
	if h.Serials[0] != 2393925 || h.Serials[1] != 2393950 {
		t.Errorf("unexpected serials: %v", h.Serials)
	}
}

func TestReadHeader_L3(t *testing.T) {
	f := openTestdata(t, "l3.updates.sample")
	h, err := ReadHeader(f)
	if err != nil {
		t.Fatal(err)
	}
	if h.Version != 1 || h.Source != "LEVEL3" {
		t.Errorf("unexpected header: %+v", h)
	}
	if h.Serials[0] != 767081 || h.Serials[1] != 767082 {
		t.Errorf("unexpected serials: %v", h.Serials)
	}
}

func TestReadHeader_StringIO(t *testing.T) {
	arinInput := `
% The ARIN Database is subject to Terms and Conditions.
% See http://www.arin.net/db/support/db-terms-conditions.pdf

%START Version: 3 ARIN 66038-66844 FILTERED

    `
	ripeInput := `
% The RIPE Database is subject to Terms and Conditions.
% See http://www.ripe.net/db/support/db-terms-conditions.pdf

%START Version: 3 RIPE 38325160-38325288

    `

	tests := []struct {
		name    string
		input   string
		version int
		source  string
		start   int
		end     int
	}{
		{"ARIN", arinInput, 3, "ARIN", 66038, 66844},
		{"RIPE", ripeInput, 3, "RIPE", 38325160, 38325288},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ReadHeader(strings.NewReader(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if h.Version != tc.version || h.Source != tc.source {
				t.Errorf("expected %d/%s, got %d/%s", tc.version, tc.source, h.Version, h.Source)
			}
			if h.Serials[0] != tc.start || h.Serials[1] != tc.end {
				t.Errorf("expected %d-%d, got %d-%d", tc.start, tc.end, h.Serials[0], h.Serials[1])
			}
		})
	}
}

func TestReadHeader_RangeErrors(t *testing.T) {
	files := []string{
		"level3.header.rangeerror.sample",
		"radb.header.rangeerror.sample",
		"ripe.header.rangeerror.sample",
	}
	ranges := [][2]int{
		{789, 765562},
		{789, 3339553},
		{2278326, 38325450},
	}

	for i, file := range files {
		t.Run(file, func(t *testing.T) {
			f := openTestdata(t, file)
			_, err := ReadHeader(f)
			var sre *SerialRangeError
			if !errors.As(err, &sre) {
				t.Fatalf("expected SerialRangeError, got %T: %v", err, err)
			}
			if sre.First != ranges[i][0] || sre.Last != ranges[i][1] {
				t.Errorf("expected %d-%d, got %d-%d", ranges[i][0], ranges[i][1], sre.First, sre.Last)
			}
		})
	}
}

func TestReadHeader_OutOfSync(t *testing.T) {
	f := openTestdata(t, "ripe.header.outofsync.sample")
	_, err := ReadHeader(f)
	var oose *OutOfSyncError
	if !errors.As(err, &oose) {
		t.Fatalf("expected OutOfSyncError, got %T: %v", err, err)
	}
}
