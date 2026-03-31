package irrd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// testNRTMv4Server sets up an httptest server serving notification, snapshot, and delta files.
type testNRTMv4Server struct {
	server  *httptest.Server
	pubKey  ed25519.PublicKey
	privKey ed25519.PrivateKey
}

func newTestNRTMv4Server(t *testing.T, nf *NotificationFile, snapshotData, deltaData map[string]string) *testNRTMv4Server {
	t.Helper()

	pubKey, privKey, _ := ed25519.GenerateKey(rand.Reader)

	// Build handlers
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)

	// Serve snapshot/delta files and compute hashes
	for path, content := range snapshotData {
		c := content // capture
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(c))
		})
		// Update hash in notification file
		hash := sha256.Sum256([]byte(content))
		nf.Snapshot.Hash = hex.EncodeToString(hash[:])
		nf.Snapshot.URL = srv.URL + path
	}

	for i := range nf.Deltas {
		path := fmt.Sprintf("/delta/%d", nf.Deltas[i].Version)
		if content, ok := deltaData[path]; ok {
			c := content
			mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(c))
			})
			hash := sha256.Sum256([]byte(content))
			nf.Deltas[i].Hash = hex.EncodeToString(hash[:])
			nf.Deltas[i].URL = srv.URL + path
		}
	}

	// Build JWS for notification file
	nfJSON, _ := json.Marshal(nf)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(nfJSON)
	signingInput := []byte(headerB64 + "." + payloadB64)
	sig := ed25519.Sign(privKey, signingInput)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jws := headerB64 + "." + payloadB64 + "." + sigB64

	mux.HandleFunc("/notification", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(jws))
	})

	return &testNRTMv4Server{
		server:  srv,
		pubKey:  pubKey,
		privKey: privKey,
	}
}

func (ts *testNRTMv4Server) Close() {
	ts.server.Close()
}

func TestUpdateNRTMv4_FreshSnapshot(t *testing.T) {
	snapshotContent := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"sess1","version":10}` + "\n" +
		"\x1e" + `{"action":"add","object_text":"route: 192.0.2.0/24\norigin: AS65001\nsource: TEST\n"}` + "\n" +
		"\x1e" + `{"action":"add","object_text":"route6: 2001:db8::/32\norigin: AS65002\nsource: TEST\n"}` + "\n"

	nf := &NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "sess1",
		Version:     10,
		Snapshot:    SnapshotRef{Version: 10, URL: "/snapshot"},
	}

	ts := newTestNRTMv4Server(t, nf, map[string]string{"/snapshot": snapshotContent}, nil)
	defer ts.Close()

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}

	cache := &WhoisCache{
		Name: "TEST",
		NRTMv4: &NRTMv4Config{
			Name:            "TEST",
			NotificationURI: ts.server.URL + "/notification",
			PublicKey:        base64.StdEncoding.EncodeToString(ts.pubKey),
		},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.updateNRTMv4(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cache.State.NRTMv4SessionID != "sess1" {
		t.Errorf("session ID = %q, want sess1", cache.State.NRTMv4SessionID)
	}
	if cache.State.NRTMv4Version != 10 {
		t.Errorf("version = %d, want 10", cache.State.NRTMv4Version)
	}
	if cache.State.Serial != "10" {
		t.Errorf("serial = %q, want 10", cache.State.Serial)
	}
	if len(cache.State.Prefix4) != 1 {
		t.Errorf("prefix4 origins = %d, want 1", len(cache.State.Prefix4))
	}
	if len(cache.State.Prefix6) != 1 {
		t.Errorf("prefix6 origins = %d, want 1", len(cache.State.Prefix6))
	}
}

func TestUpdateNRTMv4_IncrementalDelta(t *testing.T) {
	// Start with a state that already has a session
	snapshotContent := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"sess1","version":10}` + "\n"

	deltaContent := "\x1e" + `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"sess1","version":11}` + "\n" +
		"\x1e" + `{"action":"add_modify","object_text":"route: 198.51.100.0/24\norigin: AS65003\nsource: TEST\n"}` + "\n"

	nf := &NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "sess1",
		Version:     11,
		Snapshot:    SnapshotRef{Version: 10, URL: "/snapshot"},
		Deltas:      []DeltaRef{{Version: 11, URL: "/delta/11"}},
	}

	ts := newTestNRTMv4Server(t, nf,
		map[string]string{"/snapshot": snapshotContent},
		map[string]string{"/delta/11": deltaContent},
	)
	defer ts.Close()

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}

	cache := &WhoisCache{
		Name: "TEST",
		NRTMv4: &NRTMv4Config{
			Name:            "TEST",
			NotificationURI: ts.server.URL + "/notification",
			PublicKey:        base64.StdEncoding.EncodeToString(ts.pubKey),
		},
		State: &WhoisCacheState{
			Serial:          "10",
			NRTMv4SessionID: "sess1",
			NRTMv4Version:   10,
			Macros:          make(map[string]StringSet),
			Prefix4:         make(map[string]StringSet),
			Prefix6:         make(map[string]StringSet),
		},
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.updateNRTMv4(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cache.State.NRTMv4Version != 11 {
		t.Errorf("version = %d, want 11", cache.State.NRTMv4Version)
	}
	if cache.State.Serial != "11" {
		t.Errorf("serial = %q, want 11", cache.State.Serial)
	}
	if !cache.State.Prefix4["AS65003"].Contains("198.51.100.0/24") {
		t.Error("expected AS65003 to have 198.51.100.0/24")
	}
}

func TestUpdateNRTMv4_SessionReset(t *testing.T) {
	snapshotContent := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"sess2","version":1}` + "\n" +
		"\x1e" + `{"action":"add","object_text":"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"}` + "\n"

	nf := &NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "sess2",
		Version:     1,
		Snapshot:    SnapshotRef{Version: 1, URL: "/snapshot"},
	}

	ts := newTestNRTMv4Server(t, nf, map[string]string{"/snapshot": snapshotContent}, nil)
	defer ts.Close()

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}

	cache := &WhoisCache{
		Name: "TEST",
		NRTMv4: &NRTMv4Config{
			Name:            "TEST",
			NotificationURI: ts.server.URL + "/notification",
			PublicKey:        base64.StdEncoding.EncodeToString(ts.pubKey),
		},
		State: &WhoisCacheState{
			Serial:          "50",
			NRTMv4SessionID: "sess1", // different session
			NRTMv4Version:   50,
			Macros:          make(map[string]StringSet),
			Prefix4:         make(map[string]StringSet),
			Prefix6:         make(map[string]StringSet),
		},
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.updateNRTMv4(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cache.State.NRTMv4SessionID != "sess2" {
		t.Errorf("session = %q, want sess2", cache.State.NRTMv4SessionID)
	}
	if cache.State.NRTMv4Version != 1 {
		t.Errorf("version = %d, want 1", cache.State.NRTMv4Version)
	}
}

func TestUpdateNRTMv4_HashMismatch(t *testing.T) {
	nf := &NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "sess1",
		Version:     10,
		Snapshot:    SnapshotRef{Version: 10, Hash: "badhash", URL: "/snapshot"},
	}

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content"))
	})
	nf.Snapshot.URL = srv.URL + "/snapshot"

	// Build unsigned JWS (no key verification)
	nfJSON, _ := json.Marshal(nf)
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(nfJSON)
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(privKey, []byte(headerB64+"."+payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jws := headerB64 + "." + payloadB64 + "." + sigB64

	mux.HandleFunc("/notification", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(jws))
	})

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}

	cache := &WhoisCache{
		Name: "TEST",
		NRTMv4: &NRTMv4Config{
			Name:            "TEST",
			NotificationURI: srv.URL + "/notification",
			// No public key → skip signature verification
		},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	err := cache.updateNRTMv4()
	if err == nil {
		t.Fatal("expected error for hash mismatch")
	}
	if _, ok := err.(*HashMismatchError); ok {
		// Direct HashMismatchError — good
	} else if !contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestDownloadAndVerifyHash(t *testing.T) {
	content := "hello world"
	hash := sha256.Sum256([]byte(content))
	expectedHash := hex.EncodeToString(hash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	body, err := downloadAndVerifyHash(srv.URL, expectedHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer body.Close()

	data, _ := io.ReadAll(body)
	if string(data) != content {
		t.Errorf("body = %q, want %q", string(data), content)
	}
}

func TestDownloadAndVerifyHash_Mismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("actual content"))
	}))
	defer srv.Close()

	_, err := downloadAndVerifyHash(srv.URL, "0000000000000000000000000000000000000000000000000000000000000000")
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

// Ensure tmpDir is writable for cache.Save() calls in tests
func init() {
	_ = os.MkdirAll("/tmp/irrd-test", 0o755)
}
