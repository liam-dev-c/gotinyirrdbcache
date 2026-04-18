package irrd

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestUpdateNRTMv4_NotificationHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{NotificationURI: srv.URL + "/notification"},
		State:     NewWhoisCacheState(),
		cachePath: filepath.Join(t.TempDir(), "TEST.cache"),
		cfg:       &Config{CacheDataDirectory: t.TempDir()},
	}
	if err := cache.updateNRTMv4(); err == nil {
		t.Fatal("expected error for HTTP 404 on notification")
	}
}

func TestUpdateNRTMv4_PublicKeyURIFetchError(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	nfJSON, _ := json.Marshal(&NotificationFile{
		NRTMVersion: 4,
		Type:        "notification",
		Source:      "TEST",
		SessionID:   "s1",
		Version:     1,
		Snapshot:    SnapshotRef{Version: 1, URL: "/snapshot"},
	})
	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payloadB64 := base64.RawURLEncoding.EncodeToString(nfJSON)
	sig := ed25519.Sign(privKey, []byte(headerB64+"."+payloadB64))
	jws := headerB64 + "." + payloadB64 + "." + base64.RawURLEncoding.EncodeToString(sig)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/notification" {
			w.Write([]byte(jws))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cache := &WhoisCache{
		Name: "TEST",
		NRTMv4: &NRTMv4Config{
			NotificationURI: srv.URL + "/notification",
			PublicKeyURI:    srv.URL + "/pubkey",
		},
		State:     NewWhoisCacheState(),
		cachePath: filepath.Join(tmpDir, "TEST.cache"),
		cfg:       &Config{CacheDataDirectory: tmpDir},
	}
	if err := cache.updateNRTMv4(); err == nil {
		t.Fatal("expected error for public key URI fetch failure")
	}
}

func TestApplyNRTMv4Snapshot_CachedFile(t *testing.T) {
	snapshotContent := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"sess1","version":5}` + "\n" +
		"\x1e" + `{"action":"add","object_text":"route: 10.0.0.0/8\norigin: AS1\nsource: TEST\n"}` + "\n"

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}
	dumpDir := cfg.DumpDir("TEST")
	os.MkdirAll(dumpDir, 0o755)

	snapshotFilename := "snapshot_v5.json"
	snapshotPath := filepath.Join(dumpDir, snapshotFilename)
	os.WriteFile(snapshotPath, []byte(snapshotContent), 0o644)

	nf := &NotificationFile{
		NRTMVersion: 4,
		SessionID:   "sess1",
		Snapshot:    SnapshotRef{Version: 5, URL: "http://example.com/" + snapshotFilename},
	}

	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{Name: "TEST"},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.applyNRTMv4Snapshot(nf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache.State.NRTMv4SessionID != "sess1" {
		t.Errorf("session = %q, want sess1", cache.State.NRTMv4SessionID)
	}
}

func TestApplyNRTMv4Snapshot_GZipped(t *testing.T) {
	snapshotContent := "\x1e" + `{"nrtm_version":4,"type":"snapshot","source":"TEST","session_id":"gz1","version":7}` + "\n" +
		"\x1e" + `{"action":"add","object_text":"route: 10.1.0.0/16\norigin: AS2\nsource: TEST\n"}` + "\n"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(snapshotContent))
	gz.Close()

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}
	dumpDir := cfg.DumpDir("TEST")
	os.MkdirAll(dumpDir, 0o755)

	snapshotFilename := "snapshot_v7.json.gz"
	snapshotPath := filepath.Join(dumpDir, snapshotFilename)
	os.WriteFile(snapshotPath, buf.Bytes(), 0o644)

	nf := &NotificationFile{
		NRTMVersion: 4,
		SessionID:   "gz1",
		Snapshot:    SnapshotRef{Version: 7, URL: "http://example.com/" + snapshotFilename},
	}

	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{Name: "TEST"},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.applyNRTMv4Snapshot(nf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cache.State.NRTMv4SessionID != "gz1" {
		t.Errorf("session = %q, want gz1", cache.State.NRTMv4SessionID)
	}
}

func TestApplyNRTMv4Snapshot_CorruptGzip(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}
	dumpDir := cfg.DumpDir("TEST")
	os.MkdirAll(dumpDir, 0o755)

	// Pre-create a corrupt .gz file so it uses the cached path
	snapshotFilename := "snapshot_v3.json.gz"
	snapshotPath := filepath.Join(dumpDir, snapshotFilename)
	os.WriteFile(snapshotPath, []byte("not a valid gzip stream"), 0o644)

	nf := &NotificationFile{
		SessionID: "sess1",
		Snapshot:  SnapshotRef{Version: 3, URL: "http://example.com/" + snapshotFilename},
	}

	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{Name: "TEST"},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.applyNRTMv4Snapshot(nf); err == nil {
		t.Fatal("expected error for corrupt cached gzip snapshot")
	}
}

func TestApplyDeltasFrom_NonContiguous(t *testing.T) {
	nf := &NotificationFile{
		Deltas: []DeltaRef{
			{Version: 11},
			{Version: 13}, // gap: 12 is missing
		},
	}
	cache := &WhoisCache{
		State: &WhoisCacheState{
			NRTMv4Version: 10,
			Macros:        make(map[string]StringSet),
			Prefix4:       make(map[string]StringSet),
			Prefix6:       make(map[string]StringSet),
		},
	}

	err := cache.applyDeltasFrom(nf, 10)
	if err == nil {
		t.Fatal("expected error for non-contiguous delta")
	}
	if _, ok := err.(*OutOfSyncError); !ok {
		t.Fatalf("expected OutOfSyncError, got %T: %v", err, err)
	}
}

func TestDownloadAndVerifyHash_HTTPNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := downloadAndVerifyHash(srv.URL, "")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestDownloadAndVerifyHash_GZip(t *testing.T) {
	content := "hello decompressed world"

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(content))
	gz.Close()
	gzContent := buf.Bytes()

	hash := sha256.Sum256(gzContent)
	expectedHash := hex.EncodeToString(hash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(gzContent)
	}))
	defer srv.Close()

	body, err := downloadAndVerifyHash(srv.URL+"/test.gz", expectedHash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer body.Close()

	data, _ := io.ReadAll(body)
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}
}

func TestDownloadAndVerifyHashToFile_HTTPNotOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := downloadAndVerifyHashToFile(srv.URL, "", filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestFetchPublicKey_Success(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(pemBlock)
	}))
	defer srv.Close()

	b64, err := fetchPublicKey(srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotBytes, _ := base64.StdEncoding.DecodeString(b64)
	if !bytes.Equal(gotBytes, derBytes) {
		t.Error("returned key bytes don't match")
	}
}

func TestFetchPublicKey_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := fetchPublicKey(srv.URL)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestFetchPublicKey_NoPEM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not a PEM block"))
	}))
	defer srv.Close()

	_, err := fetchPublicKey(srv.URL)
	if err == nil {
		t.Fatal("expected error for non-PEM content")
	}
}

func TestUpdateNRTMv4_InvalidJWS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("notavalidjws"))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{NotificationURI: srv.URL},
		State:     NewWhoisCacheState(),
		cachePath: filepath.Join(tmpDir, "TEST.cache"),
		cfg:       &Config{CacheDataDirectory: tmpDir},
	}
	if err := cache.updateNRTMv4(); err == nil {
		t.Fatal("expected error for invalid JWS format")
	}
}

func TestUpdateNRTMv4_InvalidNotificationPayload(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{notjson}`))
	jws := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("fakesig"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(jws))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{NotificationURI: srv.URL},
		State:     NewWhoisCacheState(),
		cachePath: filepath.Join(tmpDir, "TEST.cache"),
		cfg:       &Config{CacheDataDirectory: tmpDir},
	}
	if err := cache.updateNRTMv4(); err == nil {
		t.Fatal("expected error for invalid notification payload JSON")
	}
}

func TestApplyNRTMv4Snapshot_DownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	cfg := &Config{CacheDataDirectory: tmpDir}

	nf := &NotificationFile{
		SessionID: "sess1",
		Snapshot:  SnapshotRef{Version: 99, URL: srv.URL + "/snapshot.json"},
	}

	cache := &WhoisCache{
		Name:      "TEST",
		NRTMv4:    &NRTMv4Config{Name: "TEST"},
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath("TEST"),
		cfg:       cfg,
	}

	if err := cache.applyNRTMv4Snapshot(nf); err == nil {
		t.Fatal("expected error for snapshot download failure")
	}
}

func TestDownloadAndVerifyHash_CorruptGzip(t *testing.T) {
	data := []byte("not a valid gzip stream at all")
	hash := sha256.Sum256(data)
	expectedHash := hex.EncodeToString(hash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(data)
	}))
	defer srv.Close()

	_, err := downloadAndVerifyHash(srv.URL+"/snapshot.gz", expectedHash)
	if err == nil {
		t.Fatal("expected error for corrupt gzip content")
	}
}

func TestDownloadAndVerifyHashToFile_HashMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("actual content"))
	}))
	defer srv.Close()

	err := downloadAndVerifyHashToFile(srv.URL, "0000000000000000000000000000000000000000000000000000000000000000", filepath.Join(t.TempDir(), "out.json"))
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
}

func TestApplyDeltasFrom_DeltaFetchError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	nf := &NotificationFile{
		Deltas: []DeltaRef{{Version: 11, URL: srv.URL + "/delta/11", Hash: ""}},
	}
	cache := &WhoisCache{
		State: &WhoisCacheState{
			NRTMv4Version: 10,
			Macros:        make(map[string]StringSet),
			Prefix4:       make(map[string]StringSet),
			Prefix6:       make(map[string]StringSet),
		},
	}

	err := cache.applyDeltasFrom(nf, 10)
	if err == nil {
		t.Fatal("expected error for delta fetch failure")
	}
}

func TestApplyDeltasFrom_AllSkipped(t *testing.T) {
	// Delta with only empty (unparseable) records — applied stays 0, return nil
	deltaContent := `{"nrtm_version":4,"type":"delta","source":"TEST","session_id":"s1","version":11}` + "\n" +
		`{"action":"add_modify","object_text":""}` + "\n"

	hash := sha256.Sum256([]byte(deltaContent))
	expectedHash := hex.EncodeToString(hash[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(deltaContent))
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	nf := &NotificationFile{
		Deltas: []DeltaRef{{Version: 11, URL: srv.URL + "/delta/11", Hash: expectedHash}},
	}
	cache := &WhoisCache{
		State: &WhoisCacheState{
			NRTMv4Version: 10,
			Macros:        make(map[string]StringSet),
			Prefix4:       make(map[string]StringSet),
			Prefix6:       make(map[string]StringSet),
		},
		cachePath: filepath.Join(tmpDir, "TEST.cache"),
		cfg:       &Config{CacheDataDirectory: tmpDir},
	}

	if err := cache.applyDeltasFrom(nf, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Ensure tmpDir is writable for cache.Save() calls in tests
func init() {
	_ = os.MkdirAll("/tmp/irrd-test", 0o755)
}
