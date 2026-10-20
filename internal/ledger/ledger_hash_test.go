package ledger

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

// Regression test (found dogfooding against the real MCP everything
// server with a Python client): a client that sends arguments with
// spaces after separators must still produce a bundle that verifies
// after export, even though the JSON encoder compacts RawMessage on
// the way out.
func TestVerifySurvivesArgsWhitespaceRoundTrip(t *testing.T) {
	for _, store := range map[string]func() Store{
		"memory": func() Store { return New() },
		"sqlite": func() Store {
			s, err := OpenSQLite(filepath.Join(t.TempDir(), "t.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			return s
		},
	} {
		s := store()
		spaced := json.RawMessage(`{"message": "hello", "n": 42}`)
		if _, err := s.Append("s1", "tool_call", "echo", spaced, "allow", ""); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append("s1", "tool_call", "echo", nil, "allow", ""); err != nil {
			t.Fatal(err)
		}
		events, err := s.Events()
		if err != nil {
			t.Fatal(err)
		}
		// Simulate the bundle path: marshal (compacts args), unmarshal, verify.
		raw, err := json.Marshal(events)
		if err != nil {
			t.Fatal(err)
		}
		var back []Event
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatal(err)
		}
		if got := string(back[0].Args); got != `{"message":"hello","n":42}` {
			t.Fatalf("expected compacted args after round trip, got %s", got)
		}
		if err := VerifyEvents(back); err != nil {
			t.Fatalf("verify after JSON round trip failed: %v", err)
		}
	}
}

// Changing an argument VALUE (not just its whitespace) must still
// break the chain under the canonical hash.
func TestValueChangeBreaksChain(t *testing.T) {
	s := New()
	if _, err := s.Append("s1", "tool_call", "echo", json.RawMessage(`{"message":"hello"}`), "allow", ""); err != nil {
		t.Fatal(err)
	}
	events, _ := s.Events()
	events[0].Args = json.RawMessage(`{"message":"goodbye"}`)
	if err := VerifyEvents(events); err == nil {
		t.Fatal("tampered argument value verified clean")
	}
}

// Events hashed with either v1 construction (raw or canonical args)
// must still verify, so pre-v2 chains do not read as tampered.
func TestLegacyHashFormsVerify(t *testing.T) {
	for _, canonical := range []bool{false, true} {
		s := New()
		e, err := s.Append("s1", "tool_call", "echo", json.RawMessage(`{"message": "hi"}`), "allow", "")
		if err != nil {
			t.Fatal(err)
		}
		legacy := e
		legacy.Hash = hashEventV1(e, canonical)
		if err := VerifyEvents([]Event{legacy}); err != nil {
			t.Fatalf("legacy (canonical=%v) event failed verify: %v", canonical, err)
		}
	}
}
