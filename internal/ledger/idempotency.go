package ledger

import "time"

// IdempotencyState is where one keyed execution stands. The states
// form the durable executor's journal. A call is recorded before
// it runs and again after. A crash mid-flight leaves a record
// whose outcome is honestly unknown, instead of silently lost.
//
//   - Held: the call waits for a human. It has never run.
//   - Started: the call was forwarded. No response arrived yet.
//   - Completed: the call ran. Its (redacted) response was kept
//     for replay, unless the response was too large to keep.
//   - Denied: a human denied the held call. Retries replay the
//     denial instead of queueing a new hold.
//   - Unknown: the gateway stopped (crash or kill) with the call
//     started. Or the upstream failed without a response. The
//     call may or may not have executed. Only a human resolution
//     says.
//   - Resolved: a human reconciled an unknown outcome. The human
//     recorded whether the call executed. A resolved-executed key
//     never re-forwards. A resolved-not-executed key may run
//     fresh.
//   - Discarded: the call never ran and never will under this
//     key. This covers a held call discarded on restart, a call
//     contained at forward, and a hold that timed out. A retry
//     runs fresh.
type IdempotencyState string

const (
	IdemHeld      IdempotencyState = "held"
	IdemStarted   IdempotencyState = "started"
	IdemCompleted IdempotencyState = "completed"
	IdemDenied    IdempotencyState = "denied"
	IdemUnknown   IdempotencyState = "unknown"
	IdemResolved  IdempotencyState = "resolved"
	IdemDiscarded IdempotencyState = "discarded"
)

// IdempotencyRecord is one keyed execution. Body holds the response
// the agent actually saw (post-redaction). This applies when the
// call completed and the response fit the replay cap. BodyTooLarge
// marks a completed call whose response was not kept. Resolution
// is "executed" or "not-executed" once State is Resolved.
type IdempotencyRecord struct {
	Key          string
	SessionID    string
	Tool         string
	ArgsHash     string
	State        IdempotencyState
	ApprovalID   string
	Status       int
	ContentType  string
	Body         []byte
	BodyTooLarge bool
	Resolution   string
	Note         string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IdemGet returns the record for one (session, key). It returns
// false when no record exists.
func (l *Ledger) IdemGet(sessionID, key string) (IdempotencyRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.idem[idemKey(sessionID, key)]
	return rec, ok, nil
}

// IdemPut inserts or replaces one record.
func (l *Ledger) IdemPut(rec IdempotencyRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.idem == nil {
		l.idem = map[string]IdempotencyRecord{}
	}
	l.idem[idemKey(rec.SessionID, rec.Key)] = rec
	return nil
}

// IdemClaim atomically claims a key for a new attempt. It inserts
// rec when no record exists. It also inserts when the existing
// record is in a terminal-never-ran state (discarded, or
// resolved-not-executed). It reports claimed=true. Otherwise it
// returns the existing record with claimed=false. The caller must
// honor that record instead of forwarding. The atomicity is what
// makes retries safe under concurrency. Two identical requests
// cannot both win.
func (l *Ledger) IdemClaim(rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.idem == nil {
		l.idem = map[string]IdempotencyRecord{}
	}
	k := idemKey(rec.SessionID, rec.Key)
	if existing, ok := l.idem[k]; ok {
		if existing.State == IdemDiscarded ||
			(existing.State == IdemResolved && existing.Resolution == "not-executed") {
			l.idem[k] = rec
			return rec, true, nil
		}
		return existing, false, nil
	}
	l.idem[k] = rec
	return rec, true, nil
}

// IdemList returns every record, oldest first.
func (l *Ledger) IdemList() ([]IdempotencyRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]IdempotencyRecord, 0, len(l.idem))
	for _, rec := range l.idem {
		out = append(out, rec)
	}
	return out, nil
}

// IdemPurgeBefore deletes records not updated since t. It reports
// how many were removed. Expiry is by last update. A live held
// or started record is never purged while it is still live.
func (l *Ledger) IdemPurgeBefore(t time.Time) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for k, rec := range l.idem {
		if rec.UpdatedAt.Before(t) {
			delete(l.idem, k)
			n++
		}
	}
	return n, nil
}

func idemKey(sessionID, key string) string {
	return sessionID + "\x00" + key
}
