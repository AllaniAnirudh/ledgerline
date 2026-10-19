// Package replay exports a session's events as an offline bundle and
// verifies bundles without trusting the host they came from.
//
// A bundle proves self-consistency: the events link to each other,
// untampered, in order. It does not prove who wrote them; that needs
// the trust root (gateway key) or external anchoring, which is Phase 2.
package replay

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// ExportJSONL writes every event in the store as one JSON object per
// line. The file is the offline bundle: replay it anywhere.
func ExportJSONL(s ledger.Store, path string) error {
	events, err := s.Events()
	if err != nil {
		return err
	}
	return writeBundle(path, events)
}

// ExportSessionJSONL writes a prefix-closed bundle: every event from
// the chain start through the session's last event. Prefix-closure is
// what keeps the bundle verifiable — a session-filtered slice would
// break the chain at its first event, since prev hashes point at
// events from other sessions. Filter by session when displaying.
func ExportSessionJSONL(s ledger.Store, sessionID, path string) error {
	events, err := s.Events()
	if err != nil {
		return err
	}
	end := -1
	for i, e := range events {
		if e.SessionID == sessionID {
			end = i
		}
	}
	if end < 0 {
		return fmt.Errorf("no events for session %q", sessionID)
	}
	return writeBundle(path, events[:end+1])
}

func writeBundle(path string, events []ledger.Event) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range events {
		if err := enc.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

// VerifyBundle re-reads a bundle file and checks the chain.
// Anyone with the file can run this; no access to the host needed.
func VerifyBundle(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var events []ledger.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		var e ledger.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return err
		}
		events = append(events, e)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return ledger.VerifyEvents(events)
}
