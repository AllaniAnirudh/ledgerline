package ledger

import "encoding/json"

// Store is the persistence backend for the event chain.
// The in-memory Ledger and the SQLiteStore both implement it;
// the gateway only ever talks to this interface.
type Store interface {
	Append(sessionID, kind, tool string, args json.RawMessage, decision, actor string) (Event, error)
	Events() ([]Event, error)
	EventsBySession(sessionID string) ([]Event, error)
	Verify() error
}
