package ledger

import (
	"encoding/json"
	"time"
)

// Store is the persistence backend for the event chain and the
// idempotency journal. The in-memory Ledger and the SQLiteStore
// both implement it; the gateway only ever talks to this interface.
// The journal rows are durable, not hash-chained: the chain stays
// the audit trail of exceptional transitions (unknown, resolved),
// while the table is the execution journal itself.
type Store interface {
	Append(sessionID, kind, tool string, args json.RawMessage, decision, actor string) (Event, error)
	Events() ([]Event, error)
	EventsBySession(sessionID string) ([]Event, error)
	Verify() error
	IdemGet(sessionID, key string) (IdempotencyRecord, bool, error)
	IdemPut(rec IdempotencyRecord) error
	IdemClaim(rec IdempotencyRecord) (IdempotencyRecord, bool, error)
	IdemList() ([]IdempotencyRecord, error)
	IdemPurgeBefore(t time.Time) (int, error)
	ToolsBaselineGet() (ToolsBaseline, bool, error)
	ToolsBaselinePut(b ToolsBaseline) error
}
