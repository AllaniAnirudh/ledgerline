package ledger

import (
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// New events use the v4 hash. The hash covers the preempted
// marker.
func TestHashV4CoversPreempted(t *testing.T) {
	s := New()
	e, err := s.AppendDetailed("s1", "policy_decision", "evil", nil, "hold", "", EventDetail{Mode: "prevent", DecisionID: "abc", PolicyHash: "deadbeef", AgentID: "agent-1", Preempted: "tools_drift"})
	if err != nil {
		t.Fatal(err)
	}
	if e.Hash != hashEvent(e) {
		t.Fatal("stored hash is not the v4 hash")
	}
	if e.Hash == hashEventV3(e) {
		t.Fatal("v4 hash must differ from the v3 hash of the same event")
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("v4 chain failed verify: %v", err)
	}
	// Tampering with the marker breaks the chain.
	events, _ := s.Events()
	events[0].Preempted = ""
	if err := VerifyEvents(events); err == nil {
		t.Fatal("tampered preempted marker verified clean")
	}
}

// A chain written with the v3 construction still verifies. Old
// chains do not read as tampered after the v4 change.
func TestLegacyV3HashVerifies(t *testing.T) {
	s := New()
	e, err := s.Append("s1", "tool_call", "echo", json.RawMessage(`{"message": "hi"}`), "allow", "")
	if err != nil {
		t.Fatal(err)
	}
	legacy := e
	legacy.Hash = hashEventV3(e)
	if err := VerifyEvents([]Event{legacy}); err != nil {
		t.Fatalf("v3 event failed verify: %v", err)
	}
	// A mixed chain verifies too: a v3 event followed by a v4 one.
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
		t.Fatalf("mixed v3/v4 chain failed verify: %v", err)
	}
}

// AppendDetailed round-trips the preempted marker through both
// stores.
func TestAppendDetailedPreemptedRoundTrip(t *testing.T) {
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
		detail := EventDetail{Mode: "prevent", DecisionID: "id-1", PolicyHash: "hash-1", AgentID: "agent-1", Preempted: "tools_drift"}
		if _, err := s.AppendDetailed("s1", "policy_decision", "evil", nil, "hold", "", detail); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Append("s1", "tool_call", "evil", nil, "allow", ""); err != nil {
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
		if got.Preempted != "tools_drift" {
			t.Fatalf("preempted marker lost on round trip: %+v", got)
		}
		// Plain Append leaves the marker empty.
		if events[1].Preempted != "" {
			t.Fatalf("plain append should leave preempted empty: %+v", events[1])
		}
		if err := s.Verify(); err != nil {
			t.Fatalf("verify failed: %v", err)
		}
	}
}

// A database written by the v3 schema opens, migrates, and keeps
// verifying. Old rows read back with an empty marker.
func TestSQLiteMigrationFromV3(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "v3.db")

	// Build a v3 database by hand: the v3 events table carries
	// the four v3 columns. No preempted_by column, user_version 0.
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
	mode       TEXT NOT NULL DEFAULT '',
	decision_id TEXT NOT NULL DEFAULT '',
	policy_hash TEXT NOT NULL DEFAULT '',
	agent_id   TEXT NOT NULL DEFAULT '',
	prev_hash  TEXT NOT NULL,
	hash       TEXT NOT NULL
)`)
	if err != nil {
		t.Fatal(err)
	}
	old := Event{
		Seq:       0,
		Timestamp: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
		SessionID: "s1",
		Kind:      "policy_decision",
		Tool:      "exec",
		Decision:  "deny",
		PrevHash:  "",
	}
	old.Hash = hashEventV3(old)
	_, err = db.Exec(`INSERT INTO events(seq, timestamp, session_id, kind, tool, args, decision, actor, mode, decision_id, policy_hash, agent_id, prev_hash, hash) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		old.Seq, old.Timestamp.Format(time.RFC3339Nano), old.SessionID, old.Kind, old.Tool, nil, old.Decision, "", "", "", "", "", old.PrevHash, old.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite on a v3 database failed: %v", err)
	}
	defer s.Close()

	// The migration added the column and stamped version 4.
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
	if !cols["preempted_by"] {
		t.Error("migration missed column \"preempted_by\"")
	}
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Errorf("user_version = %d, want 4", version)
	}

	// The old event reads back with an empty marker and verifies.
	events, err := s.Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
	if events[0].Preempted != "" {
		t.Fatalf("old event should read back with an empty marker: %+v", events[0])
	}
	if err := s.Verify(); err != nil {
		t.Fatalf("migrated chain failed verify: %v", err)
	}
}
