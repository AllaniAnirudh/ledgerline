// Package ledger is an append-only, hash-chained event log.
//
// Every event commits to the hash of its predecessor, so any tampering
// with history breaks the chain. Verification proves self-consistency:
// the log you read is the log that was written, in order.
//
// v0 keeps the log in memory. The SQLite/Postgres backend lands with
// the Phase 1 wedge. The hash construction does not change.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Event is a single witnessed action at the boundary.
type Event struct {
	Seq       uint64          `json:"seq"`
	Timestamp time.Time       `json:"timestamp"`
	SessionID string          `json:"session_id"`
	Kind      string          `json:"kind"` // tool_call, policy_decision, approval
	Tool      string          `json:"tool,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Decision  string          `json:"decision,omitempty"`
	Actor     string          `json:"actor,omitempty"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// Ledger is a concurrency-safe, in-memory event chain.
type Ledger struct {
	mu     sync.Mutex
	events []Event
}

func New() *Ledger { return &Ledger{} }

// Append records one event and returns it with its chain position and hash.
func (l *Ledger) Append(sessionID, kind, tool string, args json.RawMessage, decision, actor string) Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	prev := ""
	if n := len(l.events); n > 0 {
		prev = l.events[n-1].Hash
	}
	e := Event{
		Seq:       uint64(len(l.events)),
		Timestamp: time.Now().UTC(),
		SessionID: sessionID,
		Kind:      kind,
		Tool:      tool,
		Args:      args,
		Decision:  decision,
		Actor:     actor,
		PrevHash:  prev,
	}
	e.Hash = hashEvent(e)
	l.events = append(l.events, e)
	return e
}

// Events returns a copy of the chain in order.
func (l *Ledger) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

// Verify recomputes the whole chain.
func (l *Ledger) Verify() error {
	return VerifyEvents(l.Events())
}

// VerifyEvents checks linkage and hashes for any slice of events,
// e.g. ones re-loaded from an exported bundle.
func VerifyEvents(events []Event) error {
	prev := ""
	for i, e := range events {
		if e.PrevHash != prev {
			return fmt.Errorf("event %d: prev hash mismatch (chain broken)", i)
		}
		if e.Hash != hashEvent(e) {
			return fmt.Errorf("event %d: hash mismatch (log tampered)", i)
		}
		prev = e.Hash
	}
	return nil
}

func hashEvent(e Event) string {
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s|%s|%s",
		e.Seq,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID, e.Kind, e.Tool, string(e.Args),
		e.Decision, e.Actor, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}
