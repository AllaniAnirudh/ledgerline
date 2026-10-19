package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
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

	resultCh  chan bool // true = approved
	decided   bool
	decidedBy string
}

// Approvals is the hold queue.
type Approvals struct {
	mu      sync.Mutex
	pending map[string]*PendingApproval
	timeout time.Duration
}

// NewApprovals builds a queue with a 5 minute hold timeout.
func NewApprovals() *Approvals {
	return &Approvals{pending: map[string]*PendingApproval{}, timeout: 5 * time.Minute}
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
			Args: p.Args, CreatedAt: p.CreatedAt,
		})
	}
	return out
}

// Decide resolves a pending approval. ok=true approves, false denies.
// The actor is recorded into the ledger by the caller.
func (a *Approvals) Decide(id string, ok bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	p, found := a.pending[id]
	if !found || p.decided {
		return false
	}
	p.decided = true
	delete(a.pending, id)
	p.resultCh <- ok
	return true
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// hold parks the agent's request until a human decides.
// On approval the original call is forwarded upstream and the real
// response goes back to the waiting agent.
func (px *Proxy) hold(w http.ResponseWriter, r *http.Request, session string, body []byte, tool string, args json.RawMessage) {
	p := &PendingApproval{
		ID:        newID(),
		SessionID: session,
		Tool:      tool,
		Args:      args,
		CreatedAt: time.Now().UTC(),
		resultCh:  make(chan bool, 1),
	}
	px.approvals.mu.Lock()
	px.approvals.pending[p.ID] = p
	px.approvals.mu.Unlock()

	if _, err := px.ledger.Append(session, "approval", tool, args, "hold", ""); err != nil {
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}

	select {
	case approved := <-p.resultCh:
		if !approved {
			px.ledger.Append(session, "approval", tool, args, "deny", p.decidedBy)
			writeJSONRPCError(w, body, "ledgerline: tool call denied by approver")
			return
		}
		px.ledger.Append(session, "approval", tool, args, "approve", p.decidedBy)
		px.ledger.Append(session, "tool_call", tool, args, "allow", p.decidedBy)
		px.forward(w, r, body)
	case <-time.After(px.approvals.timeout):
		px.approvals.mu.Lock()
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		px.ledger.Append(session, "approval", tool, args, "timeout", "")
		writeJSONRPCError(w, body, fmt.Sprintf("ledgerline: approval timed out after %s", px.approvals.timeout))
	}
}

// serveAPI handles the control plane: approvals, session events,
// chain verification, and the replay viewer.
func (px *Proxy) serveAPI(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/v1/approvals" && r.Method == http.MethodGet:
		writeJSON(w, px.approvals.List())

	case strings.HasPrefix(r.URL.Path, "/v1/approvals/") && strings.HasSuffix(r.URL.Path, "/decision") && r.Method == http.MethodPost:
		px.decideApproval(w, r)

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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(replay.ViewerHTML())

	default:
		http.NotFound(w, r)
	}
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

	px.approvals.mu.Lock()
	p, found := px.approvals.pending[id]
	if found {
		p.decidedBy = req.Actor
	}
	px.approvals.mu.Unlock()

	if !px.approvals.Decide(id, approved) {
		http.Error(w, "approval not found or already decided", http.StatusNotFound)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "decision": req.Decision})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
