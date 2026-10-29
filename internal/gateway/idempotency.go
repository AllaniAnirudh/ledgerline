package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// The durable executor, after Replit's Durable Executor component:
// every keyed tool call is recorded before it runs and again after,
// so a crash mid-flight leaves an honestly unknown outcome instead
// of a silent double-execution on retry.
//
// A client opts in per call with the X-Ledgerline-Idempotency-Key
// header. The key is scoped to its ledger session, and it is bound
// to one tool and one canonical-arguments hash: reusing a key with
// a different tool or different arguments is denied outright, the
// way a mismatched idempotency key is everywhere else.
//
// States and what a retry gets (see ledger.IdempotencyState):
//
//   - completed: the recorded response, verbatim, with no upstream
//     call. A response over the replay cap completes but is not
//     kept; its retry is refused with an explicit "check upstream"
//     error, never re-forwarded.
//   - denied: the approver's denial, replayed.
//   - held: the same hold, by approval id, without queueing a
//     second hold. The first request still owns the forward.
//   - started: an in-flight error. The call is running; the retry
//     must wait for the first request, not run a second copy.
//   - unknown: an error telling the caller to resolve first. Only
//     a human resolution (executed / not-executed) moves it.
//   - resolved-executed: refused, never re-forwarded.
//   - resolved-not-executed, discarded: treated as fresh; the new
//     attempt claims the key again.
//
// What it does not do: unkeyed calls have no journal entry and no
// replay (they behave exactly as before); policy denials leave no
// record, so a later retry re-evaluates current policy; a replay
// bypasses current policy by design (same key means same call),
// but never bypasses containment, which is checked first; and in
// in-memory mode (--db empty) the journal lives only as long as
// the process, so restart recovery needs a SQLite ledger.
const (
	idemHeader     = "X-Ledgerline-Idempotency-Key"
	idemMaxKeyLen  = 256
	idemMaxBody    = 1 << 20
	idemMaxRecords = 1000
	idemMaxAge     = 24 * time.Hour
)

// idemClaim is one request's stake in a keyed attempt. It travels
// from the tool-call gate into hold() or forward().
type idemClaim struct {
	key      string
	tool     string
	argsHash string
}

func idemArgsHash(args json.RawMessage) string {
	sum := sha256.Sum256([]byte(canonicalArgs(args)))
	return hex.EncodeToString(sum[:])
}

// claimIdem claims a key for a new attempt in the given state,
// enforcing the journal cap: expired records are purged first, and
// a still-full journal fails closed rather than dropping history.
// The store claim itself is atomic; idemMu makes the
// purge-count-claim sequence exact under concurrency.
func (px *Proxy) claimIdem(rec ledger.IdempotencyRecord) (ledger.IdempotencyRecord, bool, error) {
	px.idemMu.Lock()
	defer px.idemMu.Unlock()
	list, err := px.ledger.IdemList()
	if err != nil {
		return ledger.IdempotencyRecord{}, false, err
	}
	if len(list) >= idemMaxRecords {
		if _, err := px.ledger.IdemPurgeBefore(time.Now().UTC().Add(-idemMaxAge)); err != nil {
			return ledger.IdempotencyRecord{}, false, err
		}
		list, err = px.ledger.IdemList()
		if err != nil {
			return ledger.IdempotencyRecord{}, false, err
		}
		if len(list) >= idemMaxRecords {
			return ledger.IdempotencyRecord{}, false, errJournalFull
		}
	}
	return px.ledger.IdemClaim(rec)
}

var errJournalFull = errString("ledgerline: idempotency journal full, boundary closed")

type errString string

func (e errString) Error() string { return string(e) }

// purgeExpiredIdem drops journal records not updated within the
// window. Best effort: a purge failure is logged, never fatal.
func (px *Proxy) purgeExpiredIdem() {
	if _, err := px.ledger.IdemPurgeBefore(time.Now().UTC().Add(-idemMaxAge)); err != nil {
		log.Printf("idempotency purge failed: %v", err)
	}
}

// idemMeta is the control-plane view of one record: everything
// except the replay body, which only a retry with the key sees.
func idemMeta(rec ledger.IdempotencyRecord) map[string]any {
	return map[string]any{
		"key": rec.Key, "session_id": rec.SessionID, "tool": rec.Tool,
		"args_hash": rec.ArgsHash, "state": string(rec.State),
		"approval_id": rec.ApprovalID, "status": rec.Status,
		"content_type": rec.ContentType, "body_too_large": rec.BodyTooLarge,
		"resolution": rec.Resolution, "note": rec.Note,
		"created_at": rec.CreatedAt, "updated_at": rec.UpdatedAt,
	}
}

// recoverIdempotency runs once at gateway start: a call that was
// started when the process died has an honestly unknown outcome,
// and a held call is gone with the in-memory hold queue, so it is
// discarded as never-executed. Both transitions are witnessed in
// the chain, so a restart never silently rewrites history.
func (px *Proxy) recoverIdempotency() error {
	list, err := px.ledger.IdemList()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, rec := range list {
		switch rec.State {
		case ledger.IdemStarted:
			rec.State = ledger.IdemUnknown
			rec.UpdatedAt = now
			if err := px.ledger.IdemPut(rec); err != nil {
				return err
			}
			if _, err := px.ledger.Append(rec.SessionID, "idempotency", rec.Tool, nil, "unknown", "gateway"); err != nil {
				return err
			}
		case ledger.IdemHeld:
			rec.State = ledger.IdemDiscarded
			rec.Note = "held call discarded on gateway restart, never executed"
			rec.UpdatedAt = now
			if err := px.ledger.IdemPut(rec); err != nil {
				return err
			}
			if _, err := px.ledger.Append(rec.SessionID, "idempotency", rec.Tool, nil, "discarded", "gateway"); err != nil {
				return err
			}
		}
	}
	return nil
}

// witnessIdem records one idempotent short-circuit in the chain,
// failing closed like every other witness: no witness, no answer.
func (px *Proxy) witnessIdem(session, tool, decision string, w http.ResponseWriter, body []byte) bool {
	return px.witness(session, "idempotency", tool, nil, decision, "", w, body)
}

// idemShortCircuit answers a retry from its journal record, when
// the record says the call must not run again. It returns true
// when it wrote a response. The caller passes the record it
// already looked up; tool and argument binding were checked there.
func (px *Proxy) idemShortCircuit(w http.ResponseWriter, body []byte, session string, rec ledger.IdempotencyRecord) bool {
	switch rec.State {
	case ledger.IdemCompleted:
		if rec.BodyTooLarge {
			if !px.witnessIdem(session, rec.Tool, "refused", w, body) {
				return true
			}
			writeJSONRPCError(w, body, "ledgerline: call previously completed but its response was too large to replay; check upstream, not re-forwarding")
			return true
		}
		if !px.witnessIdem(session, rec.Tool, "replayed", w, body) {
			return true
		}
		replayIdem(w, rec)
		return true
	case ledger.IdemDenied:
		if !px.witnessIdem(session, rec.Tool, "denied", w, body) {
			return true
		}
		writeJSONRPCError(w, body, "ledgerline: call previously denied by approver; not re-forwarding")
		return true
	case ledger.IdemHeld:
		if !px.witnessIdem(session, rec.Tool, "held", w, body) {
			return true
		}
		writeHeldAgain(w, body, rec.ApprovalID)
		return true
	case ledger.IdemStarted:
		if !px.witnessIdem(session, rec.Tool, "in-flight", w, body) {
			return true
		}
		writeJSONRPCError(w, body, "ledgerline: call already in flight; outcome not yet known")
		return true
	case ledger.IdemUnknown:
		if !px.witnessIdem(session, rec.Tool, "unknown", w, body) {
			return true
		}
		writeJSONRPCError(w, body, "ledgerline: call outcome unknown; resolve it first (ledgerline resolve)")
		return true
	case ledger.IdemResolved:
		if rec.Resolution == "executed" {
			if !px.witnessIdem(session, rec.Tool, "refused", w, body) {
				return true
			}
			writeJSONRPCError(w, body, "ledgerline: call previously executed (resolved); not re-forwarding")
			return true
		}
	}
	return false
}

// replayIdem writes a recorded response verbatim: status,
// content type, and the body the agent originally saw.
func replayIdem(w http.ResponseWriter, rec ledger.IdempotencyRecord) {
	if rec.ContentType != "" {
		w.Header().Set("Content-Type", rec.ContentType)
	}
	status := rec.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(rec.Body)
}

func writeHeldAgain(w http.ResponseWriter, body []byte, approvalID string) {
	writeJSONRPCError(w, body, "ledgerline: call already held, approval id "+approvalID)
}

// limitedBuffer keeps the first cap bytes of a response and flags
// overflow instead of failing: a response over the cap still
// reaches the agent in full, it just is not kept for replay.
type limitedBuffer struct {
	buf      []byte
	cap      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.overflow {
		return len(p), nil
	}
	room := b.cap - len(b.buf)
	if room <= 0 {
		b.overflow = true
		return len(p), nil
	}
	if len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.overflow = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

// captureWriter tees response bytes into a limited buffer while
// passing them through, and records the status code.
type captureWriter struct {
	http.ResponseWriter
	buf    *limitedBuffer
	status int
}

func (c *captureWriter) WriteHeader(status int) {
	c.status = status
	c.ResponseWriter.WriteHeader(status)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	_, _ = c.buf.Write(p)
	return c.ResponseWriter.Write(p)
}

// serveIdempotencyList answers GET /v1/idempotency, optionally
// filtered by ?state=.
func (px *Proxy) serveIdempotencyList(w http.ResponseWriter, r *http.Request) {
	px.purgeExpiredIdem()
	list, err := px.ledger.IdemList()
	if err != nil {
		http.Error(w, "ledger read failed", http.StatusInternalServerError)
		return
	}
	want := r.URL.Query().Get("state")
	out := make([]map[string]any, 0, len(list))
	for _, rec := range list {
		if want != "" && string(rec.State) != want {
			continue
		}
		out = append(out, idemMeta(rec))
	}
	writeJSON(w, out)
}

// resolveRequest is the body of POST /v1/idempotency/resolve.
type resolveRequest struct {
	Session    string `json:"session"`
	Key        string `json:"key"`
	Resolution string `json:"resolution"` // executed | not-executed
	Note       string `json:"note"`
	Actor      string `json:"actor"`
}

// serveIdempotencyResolve reconciles one unknown outcome. Only an
// unknown record can be resolved: resolving anything else would
// rewrite a known outcome.
func (px *Proxy) serveIdempotencyResolve(w http.ResponseWriter, r *http.Request) {
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad resolve body", http.StatusBadRequest)
		return
	}
	if req.Session == "" || req.Key == "" {
		http.Error(w, "resolve needs session and key", http.StatusBadRequest)
		return
	}
	if req.Resolution != "executed" && req.Resolution != "not-executed" {
		http.Error(w, "resolution must be executed or not-executed", http.StatusBadRequest)
		return
	}
	actor := req.Actor
	if name, bound := px.approverActor(r); bound {
		if actor != "" && actor != name {
			http.Error(w, "actor does not match the approver token", http.StatusForbidden)
			return
		}
		actor = name
	}
	rec, found, err := px.ledger.IdemGet(req.Session, req.Key)
	if err != nil {
		http.Error(w, "ledger read failed", http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "idempotency record not found", http.StatusNotFound)
		return
	}
	if rec.State != ledger.IdemUnknown {
		http.Error(w, "only an unknown outcome can be resolved", http.StatusBadRequest)
		return
	}
	rec.State = ledger.IdemResolved
	rec.Resolution = req.Resolution
	rec.Note = req.Note
	rec.UpdatedAt = time.Now().UTC()
	if err := px.ledger.IdemPut(rec); err != nil {
		http.Error(w, "ledger write failed", http.StatusInternalServerError)
		return
	}
	if _, err := px.ledger.Append(req.Session, "idempotency", rec.Tool, nil, "resolved", actor); err != nil {
		http.Error(w, "ledger write failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, idemMeta(rec))
}

// idemTransition moves one record to a new state, best effort: it
// is called after the agent already has its answer, so a failure
// is logged, never turned into a second response.
func (px *Proxy) idemTransition(session, key string, state ledger.IdempotencyState, mutate func(*ledger.IdempotencyRecord)) {
	rec, found, err := px.ledger.IdemGet(session, key)
	if err != nil || !found {
		log.Printf("idempotency transition failed for %s/%s: found=%v err=%v", session, key, found, err)
		return
	}
	rec.State = state
	if mutate != nil {
		mutate(&rec)
	}
	rec.UpdatedAt = time.Now().UTC()
	if err := px.ledger.IdemPut(rec); err != nil {
		log.Printf("idempotency transition failed for %s/%s: %v", session, key, err)
	}
}
