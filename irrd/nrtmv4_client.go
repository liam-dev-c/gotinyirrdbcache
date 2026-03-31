package irrd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// updateNRTMv4 performs an NRTMv4 update cycle:
// 1. Fetch and verify the Update Notification File
// 2. If session changed or no prior state, download full snapshot
// 3. Otherwise, apply incremental deltas
func (c *WhoisCache) updateNRTMv4() error {
	// Fetch notification file
	log.Printf("NRTMv4: fetching notification file from %s", c.NRTMv4.NotificationURI)
	resp, err := http.Get(c.NRTMv4.NotificationURI)
	if err != nil {
		return fmt.Errorf("NRTMv4: fetching notification file: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NRTMv4: notification file HTTP %d", resp.StatusCode)
	}

	jwsData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("NRTMv4: reading notification file: %w", err)
	}

	// Verify JWS signature
	if c.NRTMv4.PublicKey == "" {
		log.Printf("NRTMv4: no public key configured, skipping signature verification")
	}

	payload, err := VerifyNotificationFile(strings.TrimSpace(string(jwsData)), c.NRTMv4.PublicKey)
	if err != nil {
		return fmt.Errorf("NRTMv4: %w", err)
	}

	nf, err := ParseNotificationFileJSON(payload)
	if err != nil {
		return fmt.Errorf("NRTMv4: %w", err)
	}

	// Resolve relative URLs against the notification file's base URL
	baseURL, err := url.Parse(c.NRTMv4.NotificationURI)
	if err != nil {
		return fmt.Errorf("NRTMv4: parsing notification URI: %w", err)
	}
	resolveNRTMv4URLs(nf, baseURL)

	log.Printf("NRTMv4: notification: source=%s session=%s version=%d", nf.Source, nf.SessionID, nf.Version)

	// Determine if we need a full snapshot or incremental deltas
	needSnapshot := c.State.NRTMv4SessionID == "" ||
		c.State.NRTMv4SessionID != nf.SessionID

	if needSnapshot {
		if c.State.NRTMv4SessionID != "" && c.State.NRTMv4SessionID != nf.SessionID {
			log.Printf("NRTMv4: session reset: %s -> %s", c.State.NRTMv4SessionID, nf.SessionID)
		}
		return c.applyNRTMv4Snapshot(nf)
	}

	return c.applyNRTMv4Deltas(nf)
}

// applyNRTMv4Snapshot downloads and applies a full NRTMv4 snapshot.
func (c *WhoisCache) applyNRTMv4Snapshot(nf *NotificationFile) error {
	log.Printf("NRTMv4: downloading snapshot version %d from %s", nf.Snapshot.Version, nf.Snapshot.URL)

	body, err := downloadAndVerifyHash(nf.Snapshot.URL, nf.Snapshot.Hash)
	if err != nil {
		return fmt.Errorf("NRTMv4 snapshot: %w", err)
	}
	defer body.Close()

	records, err := ParseNRTMv4Snapshot(body)
	if err != nil {
		return fmt.Errorf("NRTMv4 snapshot: %w", err)
	}

	freshState := NewWhoisCacheState()
	serial := strconv.Itoa(nf.Snapshot.Version)
	for _, rec := range records {
		freshState.ApplyUpdate(Update{Action: "ADD", Serial: serial, Record: rec})
	}

	freshState.NRTMv4SessionID = nf.SessionID
	freshState.NRTMv4Version = nf.Snapshot.Version
	freshState.Serial = serial

	c.State = freshState

	// Also apply any deltas after the snapshot
	if err := c.applyDeltasFrom(nf, nf.Snapshot.Version); err != nil {
		return err
	}

	log.Printf("NRTMv4: snapshot loaded, version %d (%d records)", nf.Snapshot.Version, len(records))
	return c.Save()
}

// applyNRTMv4Deltas applies incremental NRTMv4 deltas from the notification file.
func (c *WhoisCache) applyNRTMv4Deltas(nf *NotificationFile) error {
	return c.applyDeltasFrom(nf, c.State.NRTMv4Version)
}

// applyDeltasFrom applies all deltas with version > fromVersion.
func (c *WhoisCache) applyDeltasFrom(nf *NotificationFile, fromVersion int) error {
	// Sort deltas by version
	deltas := make([]DeltaRef, len(nf.Deltas))
	copy(deltas, nf.Deltas)
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].Version < deltas[j].Version })

	// Filter to deltas we need
	var needed []DeltaRef
	for _, d := range deltas {
		if d.Version > fromVersion {
			needed = append(needed, d)
		}
	}

	if len(needed) == 0 {
		log.Printf("NRTMv4: no new deltas (at version %d)", fromVersion)
		return nil
	}

	// Verify contiguity
	expectedVersion := fromVersion + 1
	for _, d := range needed {
		if d.Version != expectedVersion {
			return &OutOfSyncError{
				Message: fmt.Sprintf("NRTMv4: non-contiguous delta: expected version %d, got %d", expectedVersion, d.Version),
			}
		}
		expectedVersion++
	}

	// Apply each delta
	applied := 0
	for _, d := range needed {
		log.Printf("NRTMv4: applying delta version %d from %s", d.Version, d.URL)

		body, err := downloadAndVerifyHash(d.URL, d.Hash)
		if err != nil {
			return fmt.Errorf("NRTMv4 delta %d: %w", d.Version, err)
		}

		updates, err := ParseNRTMv4Delta(body)
		body.Close()
		if err != nil {
			return fmt.Errorf("NRTMv4 delta %d: %w", d.Version, err)
		}

		serial := strconv.Itoa(d.Version)
		for _, u := range updates {
			u.Serial = serial
			c.State.ApplyUpdate(u)
		}

		c.State.NRTMv4Version = d.Version
		c.State.Serial = serial
		applied += len(updates)
	}

	if applied > 0 {
		log.Printf("NRTMv4: applied %d updates across %d deltas (now at version %d)", applied, len(needed), c.State.NRTMv4Version)
		return c.Save()
	}

	return nil
}

// downloadAndVerifyHash downloads a URL and verifies the SHA-256 hash of its content.
// Returns a ReadCloser that yields the verified content.
func downloadAndVerifyHash(url, expectedHash string) (io.ReadCloser, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}

	// Read full body to verify hash before returning
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}

	if expectedHash != "" {
		hash := sha256.Sum256(data)
		actual := hex.EncodeToString(hash[:])
		if !strings.EqualFold(actual, expectedHash) {
			return nil, &HashMismatchError{
				URL:      url,
				Expected: expectedHash,
				Actual:   actual,
			}
		}
	}

	return io.NopCloser(strings.NewReader(string(data))), nil
}

// resolveNRTMv4URLs resolves relative URLs in the notification file against the base URL.
func resolveNRTMv4URLs(nf *NotificationFile, base *url.URL) {
	nf.Snapshot.URL = resolveURL(base, nf.Snapshot.URL)
	for i := range nf.Deltas {
		nf.Deltas[i].URL = resolveURL(base, nf.Deltas[i].URL)
	}
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(base *url.URL, ref string) string {
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(parsed).String()
}
