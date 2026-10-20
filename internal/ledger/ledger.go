// Package ledger is an append-only, hash-chained event log.
//
// Every event commits to the hash of its predecessor, so any tampering
// with history breaks the chain. Verification proves self-consistency:
// the log you read is the log that was written, in order.
//
// Two Store backends implement the same chain: the in-memory Ledger
// below and SQLiteStore (sqlite.go). The hash construction is shared.
package ledger

import (
	"bytes"
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
func (l *Ledger) Append(sessionID, kind, tool string, args json.RawMessage, decision, actor string) (Event, error) {
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
	return e, nil
}

// Events returns a copy of the chain in order.
func (l *Ledger) Events() ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out, nil
}

// EventsBySession returns one session's events in order.
func (l *Ledger) EventsBySession(sessionID string) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []Event
	for _, e := range l.events {
		if e.SessionID == sessionID {
			out = append(out, e)
		}
	}
	return out, nil
}

// Verify recomputes the whole chain.
func (l *Ledger) Verify() error {
	events, err := l.Events()
	if err != nil {
		return err
	}
	return VerifyEvents(events)
}

// VerifyEvents checks linkage and hashes for any slice of events,
// e.g. ones re-loaded from an exported bundle.
func VerifyEvents(events []Event) error {
	prev := ""
	for i, e := range events {
		if e.PrevHash != prev {
			return fmt.Errorf("event %d: prev hash mismatch (chain broken)", i)
		}
		if !hashMatches(e) {
			return fmt.Errorf("event %d: hash mismatch (log tampered)", i)
		}
		prev = e.Hash
	}
	return nil
}

// hashEvent is the current hash construction (v2): every field is
// length-prefixed, so two different field splits can never produce
// the same preimage.
func hashEvent(e Event) string {
	h := sha256.New()
	fields := []string{
		fmt.Sprint(e.Seq),
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID, e.Kind, e.Tool, canonicalArgs(e.Args),
		e.Decision, e.Actor, e.PrevHash,
	}
	for _, f := range fields {
		fmt.Fprintf(h, "%d:%s", len(f), f)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// hashMatches accepts the current construction and both v1 forms,
// so chains written before the v2 change (and before the canonical
// args fix) still verify instead of reporting themselves tampered.
// New events are only ever written with the current construction.
func hashMatches(e Event) bool {
	return e.Hash == hashEvent(e) ||
		e.Hash == hashEventV1(e, true) ||
		e.Hash == hashEventV1(e, false)
}

// hashEventV1 is the original pipe-joined construction. canonical
// selects the argument form: true hashes the compacted arguments
// (the brief v1.1 form), false hashes the raw stored bytes (v1.0).
func hashEventV1(e Event, canonical bool) string {
	args := string(e.Args)
	if canonical {
		args = canonicalArgs(e.Args)
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d|%s|%s|%s|%s|%s|%s|%s|%s",
		e.Seq,
		e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.SessionID, e.Kind, e.Tool, args,
		e.Decision, e.Actor, e.PrevHash)
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalArgs returns the compacted form of a JSON arguments blob.
// The same call can arrive with different whitespace (Python's
// json.dumps spaces its separators; Go's encoder compacts), and the
// bundle writer compacts RawMessage again on export. Hashing the
// canonical form keeps Append, live Verify, and offline bundle
// verification in agreement. Invalid JSON hashes as-is.
func canonicalArgs(args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, args); err != nil {
		return string(args)
	}
	return buf.String()
}
