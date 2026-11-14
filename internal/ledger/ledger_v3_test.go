package ledger

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// New events use the v3 hash. The hash covers the four new fields.
func TestHashV3CoversNewFields(t *testing.T) {
	s := New()
	e, err := s.AppendDetailed("s1", "policy_decision", "exec", nil, "deny", "", EventDetail{Mode: "detect", DecisionID: "abc", PolicyHash: "deadbeef", AgentID: "agent-1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != hashEvent(e) {
		t.Fatal("stored hash is not the v3 hash")
	}
	if e.Hash == hashEventV2(e) {
		t.Fatal("v3 hash must differ from the v2 hash of the same event")
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("v3 chain failed verify: %v", err)
	}
	// Tampering with a new field breaks the chain.
	events, _ := s.Events()
	events[0].Mode = "prevent"
	if err := VerifyEvents(events); err == nil {
		t.Fatal("tampered mode verified clean")
	}
	events, _ = s.Events()
	events[0].DecisionID = "other"
	if err := VerifyEvents(events); err == nil {
		t.Fatal("tampered decision id verified clean")
	}
	events, _ = s.Events()
	events[0].PolicyHash = "other"
	if err := VerifyEvents(events); err == nil {
		t.Fatal("tampered policy hash verified clean")
	}
}

// A chain written with the v2 construction still verifies. Old
// chains do not read as tampered after the v3 change.
func TestLegacyV2HashVerifies(t *testing.T) {
	s := New()
	e, err := s.Append("s1", "tool_call", "echo", json.RawMessage(`{"message": "hi"}`), "allow", "")
	if err != nil {
		t.Fatal(err)
	}
	legacy := e
	legacy.Hash = hashEventV2(e)
	if err := VerifyEvents([]Event{legacy}); err != nil {
		t.Fatalf("v2 event failed verify: %v", err)
	}
	// A mixed chain verifies too: a v2 event followed by a v3 one.
	e2 := Event{
		Seq:       1,
		Timestamp: time.Now().UTC(),
		SessionID: "s1",
		Kind:      "tool_call",
		Tool:      "echo",
		Decision:  "allow",
		PrevHash:  legacy.Hash,
	}
	e2.Hash = hashEvent(e2)
	if err := VerifyEvents([]Event{legacy, e2}); err != nil {
		t.Fatalf("mixed v2/v3 chain failed verify: %v", err)
	}
}

// AppendDetailed round-trips the extra fields through both stores.
func TestAppendDetailedRoundTrip(t *testing.T) {
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
		detail := EventDetail{Mode: "detect", DecisionID: "id-1", PolicyHash: "hash-1", AgentID: "agent-1"}
		if _, err := s.AppendDetailed("s1", "policy_decision", "exec", nil, "deny", "", detail); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append("s1", "tool_call", "exec", nil, "allow", ""); err != nil {
			t.Fatal(err)
		}
		events, err := s.Events()
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 2 {
			t.Fatalf("want 2 events, got %d", len(events))
		}
		got := events[0]
		if got.Mode != "detect" || got.DecisionID != "id-1" || got.PolicyHash != "hash-1" || got.AgentID != "agent-1" {
			t.Fatalf("detail lost on round trip: %+v", got)
		}
		// Plain Append leaves the new fields empty.
		if events[1].Mode != "" || events[1].DecisionID != "" || events[1].PolicyHash != "" || events[1].AgentID != "" {
			t.Fatalf("plain append should leave new fields empty: %+v", events[1])
		}
		if err := s.Verify(); err != nil {
			t.Fatalf("verify failed: %v", err)
		}
	}
}

// A database written by the v2 schema opens, migrates, and keeps
// verifying. Old rows read back with empty new fields.
func TestSQLiteMigrationFromV2(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v2.db")

	// Build a v2 database by hand: the old events table only.
	// No new columns, user_version 0.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE events (
	seq        INTEGER PRIMARY KEY,
	timestamp  TEXT NOT NULL,
	session_id TEXT NOT NULL,
	kind       TEXT NOT NULL,
	tool       TEXT,
	args       TEXT,
	decision   TEXT,
	actor      TEXT,
	prev_hash  TEXT NOT NULL,
	hash       TEXT NOT NULL
)`)
	if err != nil {
		t.Fatal(err)
	}
	old := Event{
		Seq:       0,
		Timestamp: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
		SessionID: "s1",
		Kind:      "policy_decision",
		Tool:      "exec",
		Decision:  "deny",
		PrevHash:  "",
	}
	old.Hash = hashEventV2(old)
	_, err = db.Exec(`INSERT INTO events(seq, timestamp, session_id, kind, tool, args, decision, actor, prev_hash, hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		old.Seq, old.Timestamp.Format(time.RFC3339Nano), old.SessionID, old.Kind, old.Tool, nil, old.Decision, "", old.PrevHash, old.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite on a v2 database failed: %v", err)
	}
	defer s.Close()

	// The migration added the columns and stamped version 3.
	rows, err := s.db.Query(`PRAGMA table_info(events)`)
	if err != nil {
		t.Fatal(err)
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull int
		var dflt any
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			t.Fatal(err)
		}
		cols[name] = true
	}
	rows.Close()
	for _, col := range []string{"mode", "decision_id", "policy_hash", "agent_id"} {
		if !cols[col] {
			t.Errorf("migration missed column %q", col)
		}
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Errorf("user_version = %d, want 3", version)
	}

	// The old event reads back with empty new fields and verifies.
	events, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Mode != "" || events[0].DecisionID != "" || events[0].PolicyHash != "" || events[0].AgentID != "" {
		t.Fatalf("old row should read back with empty new fields: %+v", events[0])
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("migrated v2 chain failed verify: %v", err)
	}

	// New appends on the migrated database use v3 and verify.
	if _, err := s.AppendDetailed("s1", "tool_call", "exec", nil, "allow", "", EventDetail{Mode: "detect", DecisionID: "id-2"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("verify after append on migrated database failed: %v", err)
	}

	// A second open is a no-op. The migration is idempotent.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("second open after migration failed: %v", err)
	}
	defer s2.Close()
	if err := s2.Verify(); err != nil {
		t.Fatalf("verify after second open failed: %v", err)
	}
}
