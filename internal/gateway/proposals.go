package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proposal is one tool call recorded for out-of-band application.
// Unlike a held call, a proposal never forwards. The agent is
// told immediately that the action was NOT executed. A human
// applies it (or denies it) afterwards, outside the gateway.
type Proposal struct {
	ID        string          `json:"id"`
	SessionID string          `json:"session_id"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	decided   bool
}

// Proposals is the pending-proposal queue. It mirrors the approvals
// queue's bound: at most maxPending entries. A retry storm cannot
// grow gateway memory without limit. Entries also expire after
// maxAge. Expiry is enforced lazily by the control-plane handlers.
// They witness each expiry in the ledger.
type Proposals struct {
	mu         sync.Mutex
	pending    map[string]*Proposal
	maxPending int
	maxAge     time.Duration
}

// NewProposals builds an empty queue. It holds 1000 entries.
// Entries expire after 24h.
func NewProposals() *Proposals {
	return &Proposals{pending: map[string]*Proposal{}, maxPending: 1000, maxAge: 24 * time.Hour}
}

// SetMaxPending changes the queue bound. Tests use a small one.
func (p *Proposals) SetMaxPending(n int) { p.maxPending = n }

// SetMaxAge changes entry expiry. Tests use a short one.
func (p *Proposals) SetMaxAge(d time.Duration) { p.maxAge = d }

// canonicalArgs compacts a JSON blob. The same arguments then
// compare equal regardless of whitespace.
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

// AddDedup records a proposal in the queue. It returns the existing
// one when an identical proposal (same session, tool, and canonical
// arguments) is already pending. Retries therefore return the same
// proposal id instead of queueing duplicates a human could apply
// twice. AddDedup reports whether the entry is new, and an error
// when the queue is full. The caller witnesses a new proposal in
// the ledger afterwards. On a ledger failure it must call Remove
// to roll back.
func (p *Proposals) AddDedup(sessionID, tool string, args json.RawMessage) (*Proposal, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := canonicalArgs(args)
	for _, pr := range p.pending {
		if pr.SessionID == sessionID && pr.Tool == tool && canonicalArgs(pr.Args) == key {
			return &Proposal{
				ID: pr.ID, SessionID: pr.SessionID, Tool: pr.Tool,
				Args: pr.Args, CreatedAt: pr.CreatedAt,
			}, false, nil
		}
	}
	if len(p.pending) >= p.maxPending {
		return nil, false, fmt.Errorf("proposal queue full")
	}
	id, err := newID()
	if err != nil {
		return nil, false, err
	}
	pr := &Proposal{
		ID:        id,
		SessionID: sessionID,
		Tool:      tool,
		Args:      args,
		CreatedAt: time.Now().UTC(),
	}
	for {
		if _, exists := p.pending[pr.ID]; !exists {
			break
		}
		fresh, err := newID()
		if err != nil {
			return nil, false, err
		}
		pr.ID = fresh
	}
	p.pending[pr.ID] = pr
	return &Proposal{
		ID: pr.ID, SessionID: pr.SessionID, Tool: pr.Tool,
		Args: pr.Args, CreatedAt: pr.CreatedAt,
	}, true, nil
}

// Remove drops a queued proposal without deciding it. It rolls
// back an entry whose ledger witness failed.
func (p *Proposals) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, id)
}

// PurgeExpired drops entries older than maxAge and returns them.
// The caller witnesses each expiry in the ledger.
func (p *Proposals) PurgeExpired(now time.Time) []*Proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []*Proposal
	for id, pr := range p.pending {
		if now.Sub(pr.CreatedAt) > p.maxAge {
			delete(p.pending, id)
			out = append(out, &Proposal{
				ID: pr.ID, SessionID: pr.SessionID, Tool: pr.Tool,
				Args: pr.Args, CreatedAt: pr.CreatedAt,
			})
		}
	}
	return out
}

// Decide resolves a proposal and returns a copy of it for the
// caller to witness in the ledger. It returns false when the ID
// is unknown or already decided.
func (p *Proposals) Decide(id string) (*Proposal, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pr, found := p.pending[id]
	if !found || pr.decided {
		return nil, false
	}
	pr.decided = true
	delete(p.pending, id)
	out := *pr
	return &out, true
}

// List returns a snapshot of pending proposals.
func (p *Proposals) List() []*Proposal {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Proposal, 0, len(p.pending))
	for _, pr := range p.pending {
		out = append(out, &Proposal{
			ID: pr.ID, SessionID: pr.SessionID, Tool: pr.Tool,
			Args: pr.Args, CreatedAt: pr.CreatedAt,
		})
	}
	return out
}

type proposalDecisionRequest struct {
	Decision string `json:"decision"` // apply | deny
	Actor    string `json:"actor"`
}

// decideProposal resolves a pending proposal. "apply" means a human
// applied the action out of band. The gateway never forwards a
// proposal itself. The actor rule matches decideApproval. A caller
// authenticated with a per-approver token is recorded under the
// bound name.
func (px *Proxy) decideProposal(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/proposals/"), "/decision")
	var req proposalDecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad decision body", http.StatusBadRequest)
		return
	}
	if !strings.EqualFold(req.Decision, "apply") && !strings.EqualFold(req.Decision, "deny") {
		http.Error(w, "decision must be apply or deny", http.StatusBadRequest)
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
	pr, ok := px.proposals.Decide(id)
	if !ok {
		http.Error(w, "proposal not found or already decided", http.StatusNotFound)
		return
	}
	decision := strings.ToLower(req.Decision)
	if _, err := px.ledger.Append(pr.SessionID, "proposal", pr.Tool, pr.Args, decision, actor); err != nil {
		log.Printf("ledger write failed on proposal %s: %v", decision, err)
	}
	writeJSON(w, map[string]any{"ok": true, "decision": decision, "actor": actor})
}

// propose records a tool call as a proposal and answers the agent
// immediately. The action was NOT executed. Nothing is forwarded.
// A retry of an identical pending proposal returns the existing id
// instead of queueing a duplicate. The ledger write fails closed.
// Without the record, there is no proposal to apply. A failed
// witness rolls the queue entry back. The human decision afterwards
// only records apply or deny. Application itself happens out of
// band, by the human, outside the gateway.
func (px *Proxy) propose(w http.ResponseWriter, session string, body []byte, tool string, args json.RawMessage) {
	pr, isNew, err := px.proposals.AddDedup(session, tool, args)
	if err != nil {
		writeJSONRPCError(w, body, "ledgerline: proposal queue full, boundary closed")
		return
	}
	text := "ledgerline: action NOT executed; recorded as proposal " + pr.ID + " for human application out of band"
	if !isNew {
		text = "ledgerline: action NOT executed; already proposed as " + pr.ID + " for human application out of band"
		px.proposeResult(w, body, text)
		return
	}
	if _, err := px.ledger.Append(session, "proposal", tool, args, "propose", ""); err != nil {
		px.proposals.Remove(pr.ID)
		log.Printf("ledger write failed on proposal: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}
	px.proposeResult(w, body, text)
}

func (px *Proxy) proposeResult(w http.ResponseWriter, body []byte, text string) {
	var m jsonRPC
	_ = json.Unmarshal(body, &m)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(nullID(m.ID)),
		"result": map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": text,
			}},
			"isError": true,
		},
	})
}

// purgeExpiredProposals drops stale proposals and witnesses each
// expiry in the ledger. The control-plane handlers call it before
// they list or decide. Expiry needs no background goroutine.
func (px *Proxy) purgeExpiredProposals() {
	for _, pr := range px.proposals.PurgeExpired(time.Now().UTC()) {
		if _, err := px.ledger.Append(pr.SessionID, "proposal", pr.Tool, pr.Args, "expired", ""); err != nil {
			log.Printf("ledger write failed on proposal expiry: %v", err)
		}
	}
}
