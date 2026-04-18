package irrd

import (
	"errors"
	"testing"
)

func TestSerialRangeError(t *testing.T) {
	err := &SerialRangeError{
		Message: "%ERROR:401: invalid range: Not within 2278326-38325450",
		First:   52221,
		Last:    1230000,
	}
	if err.Error() != "%ERROR:401: invalid range: Not within 2278326-38325450" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	if err.First != 52221 {
		t.Errorf("expected First 52221, got %d", err.First)
	}
	if err.Last != 1230000 {
		t.Errorf("expected Last 1230000, got %d", err.Last)
	}

	// Verify errors.As works
	var target *SerialRangeError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for SerialRangeError")
	}
}

func TestOutOfSyncError(t *testing.T) {
	err := &OutOfSyncError{Message: "out of sync"}
	if err.Error() != "out of sync" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	var target *OutOfSyncError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for OutOfSyncError")
	}
}

func TestErrorResponse(t *testing.T) {
	err := &ErrorResponse{Message: "general error"}
	if err.Error() != "general error" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	var target *ErrorResponse
	if !errors.As(err, &target) {
		t.Error("errors.As failed for ErrorResponse")
	}
}

func TestParseFailure(t *testing.T) {
	err := &ParseFailure{Message: "cannot parse"}
	if err.Error() != "cannot parse" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	var target *ParseFailure
	if !errors.As(err, &target) {
		t.Error("errors.As failed for ParseFailure")
	}
}

func TestSessionResetError(t *testing.T) {
	err := &SessionResetError{OldSession: "old-id", NewSession: "new-id"}
	expected := "NRTMv4 session reset: old-id -> new-id"
	if err.Error() != expected {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	var target *SessionResetError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for SessionResetError")
	}
}

func TestSignatureError(t *testing.T) {
	err := &SignatureError{Message: "invalid signature"}
	if err.Error() != "invalid signature" {
		t.Errorf("unexpected Error(): %s", err.Error())
	}
	var target *SignatureError
	if !errors.As(err, &target) {
		t.Error("errors.As failed for SignatureError")
	}
}
