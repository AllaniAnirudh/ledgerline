package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/replay"
)

// PendingApproval is one tool call held at the boundary waiting for a
// human. The agent's request blocks until it is approved, denied, or
// the hold times out.
type PendingApproval struct {
	ID        string          `json:"id"`
	SessionID string          `json:"session_id"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`

	resultCh chan decisionResult
	decided  bool
}

type decisionResult struct {
	approved bool
	actor    string
}

// Approvals is the hold queue.
type Approvals struct {
	mu         sync.Mutex
	pending    map[string]*PendingApproval
	timeout    time.Duration
	maxPending int
}

// NewApprovals builds a queue with a 5 minute hold timeout.
func NewApprovals() *Approvals {
	return &Approvals{pending: map[string]*PendingApproval{}, timeout: 5 * time.Minute, maxPending: 1000}
}

// SetTimeout changes how long a held call waits for a human.
func (a *Approvals) SetTimeout(d time.Duration) { a.timeout = d }

// List returns a snapshot of pending approvals.
func (a *Approvals) List() []*PendingApproval {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*PendingApproval, 0, len(a.pending))
	for _, p := range a.pending {
		out = append(out, &PendingApproval{
			ID: p.ID, SessionID: p.SessionID, Tool: p.Tool,
			Args: p.Args, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt,
		})
	}
	return out
}

// Decide resolves a pending approval and records the actor who won
// the decision, atomically: the actor is set under the same lock that
// claims the decision, so the ledger can never record a loser's name
// against the winner's call. Returns false when the ID is unknown or
// already decided.
func (a *Approvals) Decide(id string, ok bool, actor string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, found := a.pending[id]
	if !found || p.decided {
		return false
	}
	p.decided = true
	delete(a.pending, id)
	p.resultCh <- decisionResult{approved: ok, actor: actor}
	return true
}

// DenySession resolves every pending approval from one session as
// denied, so a contained session's held calls do not hang until
// timeout. Returns how many were denied.
func (a *Approvals) DenySession(sessionID, actor string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, p := range a.pending {
		if p.SessionID != sessionID || p.decided {
			continue
		}
		p.decided = true
		delete(a.pending, p.ID)
		p.resultCh <- decisionResult{approved: false, actor: actor}
		n++
	}
	return n
}

func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// hold parks the agent's request until a human decides.
// On approval the original call is forwarded upstream and the real
// response goes back to the waiting agent. The release path fails
// closed, like the rest of the boundary: if the approval cannot be
// written to the ledger, the call does not pass.
func (px *Proxy) hold(w http.ResponseWriter, r *http.Request, session string, body []byte, tool string, args json.RawMessage) {
	id, err := newID()
	if err != nil {
		writeJSONRPCError(w, body, "ledgerline: cannot allocate approval id, boundary closed")
		return
	}
	p := &PendingApproval{
		ID:        id,
		SessionID: session,
		Tool:      tool,
		Args:      args,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(px.approvals.timeout),
		resultCh:  make(chan decisionResult, 1),
	}
	px.approvals.mu.Lock()
	if len(px.approvals.pending) >= px.approvals.maxPending {
		px.approvals.mu.Unlock()
		writeJSONRPCError(w, body, "ledgerline: approval queue full, boundary closed")
		return
	}
	for {
		if _, exists := px.approvals.pending[p.ID]; !exists {
			break
		}
		fresh, err := newID()
		if err != nil {
			px.approvals.mu.Unlock()
			writeJSONRPCError(w, body, "ledgerline: cannot allocate approval id, boundary closed")
			return
		}
		p.ID = fresh
	}
	px.approvals.pending[p.ID] = p
	px.approvals.mu.Unlock()

	removePending := func() {
		px.approvals.mu.Lock()
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
	}

	if _, err := px.ledger.Append(session, "approval", tool, args, "hold", ""); err != nil {
		removePending()
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}

	timer := time.NewTimer(px.approvals.timeout)
	defer timer.Stop()
	select {
	case res := <-p.resultCh:
		px.release(w, r, session, body, tool, args, res)
	case <-timer.C:
		// Claim the entry under the lock so a decision and a
		// timeout can never both win the same hold.
		px.approvals.mu.Lock()
		if p.decided {
			// The decision won the race; its result is already
			// in the buffered channel.
			px.approvals.mu.Unlock()
			px.release(w, r, session, body, tool, args, <-p.resultCh)
			return
		}
		p.decided = true
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		if _, err := px.ledger.Append(session, "approval", tool, args, "timeout", ""); err != nil {
			log.Printf("ledger write failed on approval timeout: %v", err)
		}
		writeJSONRPCError(w, body, fmt.Sprintf("ledgerline: approval timed out after %s", px.approvals.timeout))
	}
}

// release records the human's decision and, when it is an approval,
// forwards the held call upstream. Any ledger failure closes the
// boundary instead of letting the call through unrecorded.
func (px *Proxy) release(w http.ResponseWriter, r *http.Request, session string, body []byte, tool string, args json.RawMessage, res decisionResult) {
	if !res.approved {
		if _, err := px.ledger.Append(session, "approval", tool, args, "deny", res.actor); err != nil {
			log.Printf("ledger write failed on approval deny: %v", err)
		}
		writeJSONRPCError(w, body, "ledgerline: tool call denied by approver")
		return
	}
	if _, err := px.ledger.Append(session, "approval", tool, args, "approve", res.actor); err != nil {
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}
	if _, err := px.ledger.Append(session, "tool_call", tool, args, "allow", res.actor); err != nil {
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}
	px.forward(w, r, body)
}

// serveAPI handles the control plane: approvals, session events,
// chain verification, and the replay viewer.
func (px *Proxy) serveAPI(w http.ResponseWriter, r *http.Request) {
	// The pages themselves are static and carry no data; every /v1
	// call behind them checks the API token when one is set.
	if strings.HasPrefix(r.URL.Path, "/v1/") && !px.tokenOK(r) {
		http.Error(w, "ledgerline: missing or bad API token", http.StatusUnauthorized)
		return
	}
	switch {
	case r.URL.Path == "/approvals" && r.Method == http.MethodGet:
		writePage(w, ApprovalsHTML())

	case strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
		px.decideApproval(w, r)

	case r.URL.Path == "/v1/approvals" && r.Method == http.MethodGet:
		writeJSON(w, px.approvals.List())

	case strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/contain") && r.Method == http.MethodPost:
		px.containSessionAPI(w, r)

	case r.URL.Path == "/v1/contained" && r.Method == http.MethodGet:
		writeJSON(w, px.ContainedList())

	case r.URL.Path == "/v1/proposals" && r.Method == http.MethodGet:
		px.purgeExpiredProposals()
		writeJSON(w, px.proposals.List())

	case strings.HasPrefix(r.URL.Path, "/v1/proposals/") && strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
		px.purgeExpiredProposals()
		px.decideProposal(w, r)

	case r.URL.Path == "/v1/upstream" && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{"upstream": RedactURL(px.upstream.String()), "pin": px.upstreamPin, "pinned": px.pinConfigured})

	case r.URL.Path == "/v1/broker" && r.Method == http.MethodGet:
		if px.broker == nil {
			writeJSON(w, map[string]any{"active": false, "credentials": []BrokerStatus{}})
			break
		}
		writeJSON(w, map[string]any{"active": true, "credentials": px.broker.Status()})

	case strings.HasPrefix(r.URL.Path, "/v1/sessions/") && strings.HasSuffix(r.URL.Path, "/events") && r.Method == http.MethodGet:
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/events")
		events, err := px.ledger.EventsBySession(id)
		if err != nil {
			http.Error(w, "ledger read failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, events)

	case r.URL.Path == "/v1/verify" && r.Method == http.MethodGet:
		if err := px.ledger.Verify(); err != nil {
			writeJSON(w, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"ok": true})

	case r.URL.Path == "/replay" && r.Method == http.MethodGet:
		writePage(w, replay.ViewerHTML())

	default:
		http.NotFound(w, r)
	}
}

// writePage serves one of the built-in pages with headers that keep
// it from being framed or extended by injected content.
func writePage(w http.ResponseWriter, html []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Write(html)
}

type decisionRequest struct {
	Decision string `json:"decision"` // approve | deny
	Actor    string `json:"actor"`
}

func (px *Proxy) decideApproval(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/approvals/"), "/decision")
	var req decisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad decision body", http.StatusBadRequest)
		return
	}
	approved := strings.EqualFold(req.Decision, "approve")
	if !approved && !strings.EqualFold(req.Decision, "deny") {
		http.Error(w, "decision must be approve or deny", http.StatusBadRequest)
		return
	}

	// When the caller authenticated with a per-approver token, the
	// actor recorded in the ledger is the name bound to that token,
	// not the free-text name in the body. A body name that disagrees
	// with the credential is rejected outright.
	actor := req.Actor
	if name, bound := px.approverActor(r); bound {
		if actor != "" && actor != name {
			http.Error(w, "actor does not match the approver token", http.StatusForbidden)
			return
		}
		actor = name
	}

	if !px.approvals.Decide(id, approved, actor) {
		http.Error(w, "approval not found or already decided", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "decision": req.Decision, "actor": actor})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
