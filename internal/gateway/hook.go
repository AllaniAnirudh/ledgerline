package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// POST /v1/hook is the harness-hook entry point. A harness calls
// it before a native tool runs. Native tools never cross the MCP
// boundary. The gateway alone cannot see them. This endpoint
// applies the same policy engine to them.
//
// The request carries the tool name, its arguments, and the
// session. The answer is allow or deny. A hold parks the call in
// the same approval queue the gateway uses. It waits for the
// human decision. The harness hook timeout bounds the wait. If
// the bridge stops waiting first, the gateway hold is cancelled.
// A late approval after that records no allow. The agent must
// retry for a fresh hold. The endpoint caps the request body
// at the same 10 MB as other gateway traffic.
//
// Drift detection does not apply here. It guards the upstream
// MCP tool surface, not native harness tools. Policy is the
// control for native tools.

type hookRequest struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Session   string          `json:"session"`
}

type hookDecision struct {
	Decision string `json:"decision"` // allow or deny
	Reason   string `json:"reason,omitempty"`
}

func (px *Proxy) serveHook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		http.Error(w, "hook body too large", http.StatusBadRequest)
		return
	}
	var req hookRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad hook body", http.StatusBadRequest)
		return
	}
	tool := strings.TrimSpace(req.Tool)
	if tool == "" {
		http.Error(w, "hook body has no tool", http.StatusBadRequest)
		return
	}
	args := req.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	session := req.Session
	if session == "" {
		session = "default"
	}

	// A contained session gets nothing. This matches the proxy
	// path. The denial is witnessed, so blocked hook attempts
	// stay visible in the ledger.
	if px.IsContained(session, "") {
		if _, err := px.ledger.Append(session, "containment", "(session)", nil, "deny", ""); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: session contained"})
		return
	}

	// A brokered secret in the arguments is denied before any
	// witness records those arguments. This matches the proxy
	// path.
	if px.broker != nil && px.broker.ContainsSecret(args) {
		if _, err := px.ledger.Append(session, "policy_decision", tool, nil, "deny", ""); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: tool arguments contain a brokered credential"})
		return
	}

	decision, reason := px.policy.DecideCall(tool, args)
	if _, err := px.ledger.Append(session, "policy_decision", tool, nil, decision.String(), ""); err != nil {
		http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
		return
	}
	switch decision {
	case policy.Allow:
		if _, err := px.ledger.Append(session, "tool_call", tool, args, "allow", ""); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "allow"})
	case policy.Deny:
		msg := "ledgerline: tool call denied by policy"
		if reason != "" {
			msg += ": " + reason
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: msg})
	case policy.Contain:
		msg := "ledgerline: session contained by policy"
		if reason != "" {
			msg += ": " + reason
		}
		px.Contain(session, "", reason)
		writeJSON(w, hookDecision{Decision: "deny", Reason: msg})
	case policy.Propose:
		pr, isNew, err := px.proposals.AddDedup(session, tool, args)
		if err != nil {
			http.Error(w, "ledgerline: proposal queue full, boundary closed", http.StatusServiceUnavailable)
			return
		}
		text := "ledgerline: action NOT executed; recorded as proposal " + pr.ID + " for human application out of band"
		if !isNew {
			text = "ledgerline: action NOT executed; already proposed as " + pr.ID + " for human application out of band"
		}
		if isNew {
			if _, err := px.ledger.Append(session, "proposal", tool, args, "propose", ""); err != nil {
				px.proposals.Remove(pr.ID)
				http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
				return
			}
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: text})
	case policy.Hold:
		writeJSON(w, px.hookHold(r, session, tool, args))
	default:
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: unknown policy decision"})
	}
}

// hookHold parks a native tool call in the approval queue. It
// waits for the human decision. It mirrors hold() in approvals.go.
// Same queue, same timeout race handling. It differs in two ways.
// There is no upstream call to forward. The decision itself is
// the answer. There is no idempotency claim. A hook call
// is a check, not a forwarded call.
func (px *Proxy) hookHold(r *http.Request, session, tool string, args json.RawMessage) hookDecision {
	id, err := newID()
	if err != nil {
		return hookDecision{Decision: "deny", Reason: "ledgerline: cannot allocate approval id, boundary closed"}
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
		return hookDecision{Decision: "deny", Reason: "ledgerline: approval queue full, boundary closed"}
	}
	for {
		if _, exists := px.approvals.pending[p.ID]; !exists {
			break
		}
		fresh, err := newID()
		if err != nil {
			px.approvals.mu.Unlock()
			return hookDecision{Decision: "deny", Reason: "ledgerline: cannot allocate approval id, boundary closed"}
		}
		p.ID = fresh
	}
	px.approvals.pending[p.ID] = p
	px.approvals.mu.Unlock()

	if _, err := px.ledger.Append(session, "approval", tool, args, "hold", ""); err != nil {
		px.approvals.mu.Lock()
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
	}

	timer := time.NewTimer(px.approvals.timeout)
	defer timer.Stop()
	select {
	case res := <-p.resultCh:
		return px.hookDecided(session, tool, args, res)
	case <-r.Context().Done():
		// The bridge left. Cancel the hold, so a late
		// approval cannot record an allow for a call that
		// never ran. A decision that raced the disconnect
		// is dropped for the same reason.
		px.approvals.mu.Lock()
		if !p.decided {
			p.decided = true
			delete(px.approvals.pending, p.ID)
		} else {
			select {
			case <-p.resultCh:
			default:
			}
		}
		px.approvals.mu.Unlock()
		if _, err := px.ledger.Append(session, "approval", tool, args, "cancelled", ""); err != nil {
			log.Printf("ledger write failed on approval cancel: %v", err)
		}
		return hookDecision{Decision: "deny", Reason: "ledgerline: bridge disconnected, approval cancelled; retry for a fresh hold"}
	case <-timer.C:
		// Claim the entry under the lock. A decision and a
		// timeout can never both win the same hold.
		px.approvals.mu.Lock()
		if p.decided {
			// The decision won the race. Its result is already
			// in the buffered channel.
			px.approvals.mu.Unlock()
			return px.hookDecided(session, tool, args, <-p.resultCh)
		}
		p.decided = true
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		if _, err := px.ledger.Append(session, "approval", tool, args, "timeout", ""); err != nil {
			log.Printf("ledger write failed on approval timeout: %v", err)
		}
		return hookDecision{Decision: "deny", Reason: fmt.Sprintf("ledgerline: approval timed out after %s", px.approvals.timeout)}
	}
}

// hookDecided records a hold decision. It turns the decision into
// an answer. An approval records the approval and the allowed
// call. A denial records the denial only.
func (px *Proxy) hookDecided(session, tool string, args json.RawMessage, res decisionResult) hookDecision {
	if res.approved {
		if _, err := px.ledger.Append(session, "approval", tool, args, "approve", res.actor); err != nil {
			return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		if _, err := px.ledger.Append(session, "tool_call", tool, args, "allow", res.actor); err != nil {
			return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookDecision{Decision: "allow"}
	}
	if _, err := px.ledger.Append(session, "approval", tool, args, "deny", res.actor); err != nil {
		log.Printf("ledger write failed on approval deny: %v", err)
	}
	return hookDecision{Decision: "deny", Reason: "ledgerline: tool call denied by approver"}
}
