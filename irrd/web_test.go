package irrd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func newTestService() *WhoisCacheService {
	state := makeStateWithData()
	state.Serial = "42"
	return &WhoisCacheService{
		Caches: map[string]*WhoisCache{
			"TEST":      {Name: "TEST", State: state, Ready: true},
			"NOT_READY": {Name: "NOT_READY", State: NewWhoisCacheState(), Ready: false},
		},
	}
}

func newTestServer() *Server {
	return NewServer(newTestService())
}

func doReq(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}
	return out
}

func TestServer_Index(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Whois Cache") {
		t.Error("expected body to contain 'Whois Cache'")
	}
	if !strings.Contains(body, "/cache/{cache}/macros/lookup/{key}") {
		t.Error("expected body to contain route documentation")
	}
}

func TestServer_Index_NotFound(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/unknown-path")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestServer_Health_Ready(t *testing.T) {
	srv := newTestServer()
	// Remove NOT_READY so at least one cache is ready
	delete(srv.Service.Caches, "NOT_READY")
	w := doReq(t, srv, "/healthz")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	if out["status"] != true {
		t.Errorf("expected status true, got %v", out["status"])
	}
}

func TestServer_Health_NotReady(t *testing.T) {
	srv := NewServer(&WhoisCacheService{
		Caches: map[string]*WhoisCache{
			"NONE": {Name: "NONE", State: NewWhoisCacheState(), Ready: false},
		},
	})
	w := doReq(t, srv, "/healthz")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestServer_WithCache_NotFound(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/MISSING/macros/list")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestServer_WithCache_NotReady(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/NOT_READY/macros/list")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestServer_LookupMacros_Found(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/macros/lookup/AS-FOO")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Errorf("expected non-empty data array, got %v", out["data"])
	}
}

func TestServer_LookupMacros_NotFound(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/macros/lookup/MISSING")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestServer_ListMacros(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/macros/list")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok || len(data) != 1 || data[0] != "AS-FOO" {
		t.Errorf("unexpected data: %v", out["data"])
	}
}

func TestServer_LookupPrefix4_Found(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/4/lookup/AS1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Errorf("expected prefixes, got %v", out["data"])
	}
}

func TestServer_LookupPrefix4_NotFound(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/4/lookup/AS999")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestServer_ListPrefix4(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/4/list")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Errorf("expected ASN list, got %v", out["data"])
	}
}

func TestServer_LookupPrefix6_Found(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/6/lookup/AS1")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Errorf("expected prefixes, got %v", out["data"])
	}
}

func TestServer_LookupPrefix6_NotFound(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/6/lookup/AS999")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestServer_ListPrefix6(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/prefixes/6/list")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestServer_Status(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/status")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", out["data"])
	}
	if data["serial"] != "42" {
		t.Errorf("expected serial 42, got %v", data["serial"])
	}
}

func TestServer_Dump(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/TEST/dump")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %v", out["data"])
	}
	if _, ok := data["macros"]; !ok {
		t.Error("expected macros key in dump")
	}
	if _, ok := data["prefix4"]; !ok {
		t.Error("expected prefix4 key in dump")
	}
	if _, ok := data["prefix6"]; !ok {
		t.Error("expected prefix6 key in dump")
	}
}

func TestServer_Update_NoSuchCache(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/MISSING/update")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func newServerWithCachePath(t *testing.T, path string) *Server {
	t.Helper()
	svc := &WhoisCacheService{
		Caches: map[string]*WhoisCache{
			"TEST": {Name: "TEST", State: NewWhoisCacheState(), cachePath: path},
		},
	}
	srv := &Server{Service: svc, mux: http.NewServeMux()}
	srv.registerRoutes()
	return srv
}

func TestServer_Update_NotReady(t *testing.T) {
	srv := newServerWithCachePath(t, "/tmp/nonexistent-irrd-test-cache-file.cache")
	w := doReq(t, srv, "/cache/TEST/update")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestServer_Update_Success(t *testing.T) {
	f, err := os.CreateTemp("", "irrd-test-*.cache")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if err := saveState(makeStateWithData(), f.Name()); err != nil {
		t.Fatal(err)
	}

	srv := newServerWithCachePath(t, f.Name())
	w := doReq(t, srv, "/cache/TEST/update")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "OK") {
		t.Errorf("expected OK body, got %s", w.Body.String())
	}
}

func TestServer_Update_CorruptFile(t *testing.T) {
	f, err := os.CreateTemp("", "irrd-test-corrupt-*.cache")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("this is not valid gob data"))
	f.Close()
	defer os.Remove(f.Name())

	srv := newServerWithCachePath(t, f.Name())
	w := doReq(t, srv, "/cache/TEST/update")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d: %s", w.Code, w.Body.String())
	}
	// Corrupt file should have been removed
	if _, err := os.Stat(f.Name()); !os.IsNotExist(err) {
		t.Error("expected corrupt cache file to be removed")
	}
}

func TestServer_AllCache(t *testing.T) {
	srv := newTestServer()
	w := doReq(t, srv, "/cache/ALL/macros/list")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	out := decodeJSON(t, w)
	data, ok := out["data"].([]interface{})
	if !ok {
		t.Fatalf("expected data array, got %v", out["data"])
	}
	found := false
	for _, v := range data {
		if v == "AS-FOO" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AS-FOO in ALL macro list, got %v", data)
	}
}

func TestServer_AllCache_Dump(t *testing.T) {
	srv := newTestServer()
	// NOT_READY is in the ALL view (combiner includes all states regardless of Ready flag)
	w := doReq(t, srv, "/cache/ALL/dump")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestParseFloat(t *testing.T) {
	f, err := parseFloat("12345")
	if err != nil || f != 12345 {
		t.Errorf("expected 12345, got %v (err=%v)", f, err)
	}
	_, err = parseFloat("not-a-number")
	if err == nil {
		t.Error("expected error for non-numeric string")
	}
}
