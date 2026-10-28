package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Proposal is one tool call recorded for out-of-band application.
// Unlike a held call, a proposal never forwards: the agent is told
// immediately that the action was NOT executed, and a human applies
// it (or denies it) afterwards, outside the gateway.
type Proposal struct {
	ID        string          `json:"id"`
	SessionID string          `json:"session_id"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	decided   bool
}

// Proposals is the pending-proposal queue.
type Proposals struct {
	mu      sync.Mutex
	pending map[string]*Proposal
}

// NewProposals builds an empty queue.
func NewProposals() *Proposals {
	return &Proposals{pending: map[string]*Proposal{}}
}

// Add records a proposal in the queue. The caller witnesses it in
// the ledger first; Add only tracks it for a later human decision.
func (p *Proposals) Add(sessionID, tool string, args json.RawMessage) (*Proposal, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	pr := &Proposal{
		ID:        id,
		SessionID: sessionID,
		Tool:      tool,
		Args:      args,
		CreatedAt: time.Now().UTC(),
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for {
		if _, exists := p.pending[pr.ID]; !exists {
			break
		}
		fresh, err := newID()
		if err != nil {
			return nil, err
		}
		pr.ID = fresh
	}
	p.pending[pr.ID] = pr
	return pr, nil
}

// Decide resolves a proposal and returns a copy of it for the
// caller to witness in the ledger. Returns false when the ID is
// unknown or already decided.
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
// applied the action out of band; the gateway never forwards a
// proposal itself. The actor rule matches decideApproval: a caller
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
// immediately: the action was NOT executed, and nothing is forwarded.
// The ledger write comes first and fails closed: without the record,
// there is no proposal to apply. The human decision afterwards only
// records apply or deny; application itself happens out of band,
// by the human, outside the gateway.
func (px *Proxy) propose(w http.ResponseWriter, session string, body []byte, tool string, args json.RawMessage) {
	if _, err := px.ledger.Append(session, "proposal", tool, args, "propose", ""); err != nil {
		log.Printf("ledger write failed on proposal: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return
	}
	pr, err := px.proposals.Add(session, tool, args)
	if err != nil {
		writeJSONRPCError(w, body, "ledgerline: cannot allocate proposal id, boundary closed")
		return
	}
	var m jsonRPC
	_ = json.Unmarshal(body, &m)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(nullID(m.ID)),
		"result": map[string]any{
			"content": []map[string]any{{
				"type": "text",
				"text": "ledgerline: action NOT executed; recorded as proposal " + pr.ID + " for human application out of band",
			}},
			"isError": true,
		},
	})
}
