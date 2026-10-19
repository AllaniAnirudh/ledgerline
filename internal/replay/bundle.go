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
	"os"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// ExportJSONL writes every event in the ledger as one JSON object per
// line. The file is the offline bundle: replay it anywhere.
func ExportJSONL(l *ledger.Ledger, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, e := range l.Events() {
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
