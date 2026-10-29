package ledger

import (
	"path/filepath"
	"testing"
)

func TestChainAppendAndVerify(t *testing.T) {
	l := New()
	for i := 0; i < 5; i++ {
		if _, err := l.Append("s1", "tool_call", "read_file", nil, "allow", ""); err != nil {
			t.Fatal(err)
		}
	}
	events, err := l.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 5 {
		t.Fatalf("want 5 events, got %d", len(events))
	}
	for i, e := range events {
		if e.Seq != uint64(i) {
			t.Fatalf("event %d has seq %d", i, e.Seq)
		}
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("chain should verify: %v", err)
	}
}

func TestChainDetectsTampering(t *testing.T) {
	l := New()
	l.Append("s1", "tool_call", "exec", nil, "allow", "")
	l.Append("s1", "tool_call", "read_file", nil, "allow", "")

	// Tamper with history behind the ledger's back.
	l.mu.Lock()
	l.events[0].Tool = "write_file"
	l.mu.Unlock()

	if err := l.Verify(); err == nil {
		t.Fatal("tampered chain verified clean")
	}
}

func TestSQLiteRoundTrip(t *testing.T) {
	s, err := OpenSQLite(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Append("s9", "policy_decision", "exec", nil, "deny", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append("s9", "approval", "exec", nil, "deny", "buppy"); err != nil {
		t.Fatal(err)
	}

	events, err := s.EventsBySession("s9")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	if events[1].Actor != "buppy" {
		t.Fatalf("actor not persisted, got %q", events[1].Actor)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("sqlite chain should verify: %v", err)
	}

	// Reopen the same file. The chain must survive the process.
	path := filepath.Join(t.TempDir(), "persist.db")
	s, err = OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Append("s9", "tool_call", "read_file", nil, "allow", "")
	s.Close()

	s2, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	events, err = s2.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 persisted event, got %d", len(events))
	}
	if err := s2.Verify(); err != nil {
		t.Fatalf("reopened chain should verify: %v", err)
	}
}
