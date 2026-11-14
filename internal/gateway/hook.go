package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
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
	// "gateway" is reserved for the gateway's own rows. A
	// hook session with that name would hide among system
	// rows. The request is rejected instead of renamed.
	if strings.EqualFold(session, "gateway") {
		http.Error(w, `ledgerline: session name "gateway" is reserved`, http.StatusBadRequest)
		return
	}

	// Agent identity comes from the token. The hook never
	// invents an id. A call with no token is unattributed.
	// The id rides the request, as on the proxy path. The
	// hold below reads it back from the request.
	agentID, ok := px.hookAgentID(w, r)
	if !ok {
		return
	}
	r = withAgentID(r, agentID)

	// A contained session gets nothing. This matches the proxy
	// path. The denial is witnessed, so blocked hook attempts
	// stay visible in the ledger.
	if px.IsContained(session, "") {
		if _, err := px.ledger.AppendDetailed(session, "containment", "(session)", nil, "deny", "", ledger.EventDetail{AgentID: agentID}); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: session contained"})
		return
	}

	// A brokered secret in the arguments is denied before any
	// witness records those arguments. This matches the proxy
	// path. This refusal is a boundary rule. Detect mode does
	// not change it. The detect promise covers policy rules
	// only. A brokered secret must never be witnessed.
	if px.broker != nil && px.broker.ContainsSecret(args) {
		if _, err := px.appendPolicyDecision(session, tool, "deny", policy.ModePrevent, agentID); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: tool arguments contain a brokered credential"})
		return
	}

	decision, reason, mode := px.policyNow().DecideCall(tool, args)
	// Detect mode changes every restrictive action the same way
	// as the proxy path. The call is allowed. The ledger records
	// the would-be decision first, then the tool_call sent to run.
	// Both carry one decision id. Hold in detect queues nothing.
	// Contain in detect freezes nothing. Propose in detect
	// records a proposal marked detected and never queues it.
	detect := mode == policy.ModeDetect && decision != policy.Allow
	decisionID, err := px.appendPolicyDecision(session, tool, decision.String(), mode, agentID)
	if err != nil {
		http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
		return
	}
	detectDetail := ledger.EventDetail{Mode: mode.String(), DecisionID: decisionID, AgentID: agentID}
	allowDetected := func() {
		if _, err := px.ledger.AppendDetailed(session, "tool_call", tool, args, "allow", "", detectDetail); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "allow"})
	}
	switch decision {
	case policy.Allow:
		if _, err := px.ledger.AppendDetailed(session, "tool_call", tool, args, "allow", "", ledger.EventDetail{AgentID: agentID}); err != nil {
			http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, hookDecision{Decision: "allow"})
	case policy.Deny:
		if detect {
			allowDetected()
			return
		}
		msg := "ledgerline: tool call denied by policy"
		if reason != "" {
			msg += ": " + reason
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: msg})
	case policy.Contain:
		if detect {
			allowDetected()
			return
		}
		msg := "ledgerline: session contained by policy"
		if reason != "" {
			msg += ": " + reason
		}
		px.Contain(session, "", reason, agentID)
		writeJSON(w, hookDecision{Decision: "deny", Reason: msg})
	case policy.Propose:
		if detect {
			// Record the proposal, marked detected. Do not
			// queue it. A human must never apply a call that
			// was already sent to run.
			if _, err := px.ledger.AppendDetailed(session, "proposal", tool, args, "propose", "", detectDetail); err != nil {
				http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
				return
			}
			allowDetected()
			return
		}
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
			if _, err := px.ledger.AppendDetailed(session, "proposal", tool, args, "propose", "", ledger.EventDetail{AgentID: agentID}); err != nil {
				px.proposals.Remove(pr.ID)
				http.Error(w, "ledgerline: ledger unavailable, boundary closed", http.StatusServiceUnavailable)
				return
			}
		}
		writeJSON(w, hookDecision{Decision: "deny", Reason: text})
	case policy.Hold:
		if detect {
			allowDetected()
			return
		}
		writeJSON(w, px.hookHold(r, session, tool, args))
	default:
		writeJSON(w, hookDecision{Decision: "deny", Reason: "ledgerline: unknown policy decision"})
	}
}

// hookAgentID resolves the agent id for one hook call. The
// token comes from the X-Ledgerline-Agent-Token header. It is
// checked the same way the proxy path checks it. When agent
// tokens are required, a missing or bad token is a 401. When
// they are not required, a token that is present is still
// checked. A bad credential must not silently drop attribution.
// No token means the call is unattributed. The hook never
// invents an id.
func (px *Proxy) hookAgentID(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok := r.Header.Get(agentTokenHeader)
	if tok == "" {
		if px.requireAgentToken {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(hookDecision{Decision: "deny", Reason: "ledgerline: missing or invalid agent token"})
			return "", false
		}
		return "", true
	}
	claims, err := px.validateAgentToken(r)
	if err != nil {
		log.Printf("ledgerline: hook auth rejected: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(hookDecision{Decision: "deny", Reason: "ledgerline: missing or invalid agent token"})
		return "", false
	}
	return claims.AgentID, true
}

// hookHold parks a native tool call in the approval queue. It
// waits for the human decision. It mirrors hold() in approvals.go.
// Same queue, same timeout race handling. It differs in two ways.
// There is no upstream call to forward. The decision itself is
// the answer. There is no idempotency claim. A hook call
// is a check, not a forwarded call.
func (px *Proxy) hookHold(r *http.Request, session, tool string, args json.RawMessage) hookDecision {
	agentID := agentIDOf(r)
	id, err := newID()
	if err != nil {
		return hookDecision{Decision: "deny", Reason: "ledgerline: cannot allocate approval id, boundary closed"}
	}
	p := &PendingApproval{
		ID:        id,
		SessionID: session,
		Tool:      tool,
		Args:      args,
		AgentID:   agentID,
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

	if _, err := px.ledger.AppendDetailed(session, "approval", tool, args, "hold", "", ledger.EventDetail{AgentID: agentID}); err != nil {
		px.approvals.mu.Lock()
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
	}

	timer := time.NewTimer(px.approvals.timeout)
	defer timer.Stop()
	select {
	case res := <-p.resultCh:
		return px.hookDecided(session, tool, args, res, agentID)
	case <-r.Context().Done():
		return px.cancelHold(p, session, tool, args)
	case <-timer.C:
		// Claim the entry under the lock. A decision and a
		// timeout can never both win the same hold.
		px.approvals.mu.Lock()
		if p.decided {
			// The decision won the race. Its result is already
			// in the buffered channel.
			px.approvals.mu.Unlock()
			return px.hookDecided(session, tool, args, <-p.resultCh, agentID)
		}
		p.decided = true
		delete(px.approvals.pending, p.ID)
		px.approvals.mu.Unlock()
		if _, err := px.ledger.AppendDetailed(session, "approval", tool, args, "timeout", "", ledger.EventDetail{AgentID: agentID}); err != nil {
			log.Printf("ledger write failed on approval timeout: %v", err)
		}
		return hookDecision{Decision: "deny", Reason: fmt.Sprintf("ledgerline: approval timed out after %s", px.approvals.timeout)}
	}
}

// cancelHold ends a hold because the bridge left. It claims
// the entry under the lock, so a late approval cannot win
// after the cancel. A decision that raced the disconnect is
// dropped. The call never ran, so no allow may be recorded
// for it. The ledger records the cancel.
func (px *Proxy) cancelHold(p *PendingApproval, session, tool string, args json.RawMessage) hookDecision {
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
	// The agent id lives on the pending approval. A hold
	// created without one stays unattributed.
	if _, err := px.ledger.AppendDetailed(session, "approval", tool, args, "cancelled", "", ledger.EventDetail{AgentID: p.AgentID}); err != nil {
		log.Printf("ledger write failed on approval cancel: %v", err)
	}
	return hookDecision{Decision: "deny", Reason: "ledgerline: bridge disconnected, approval cancelled; retry for a fresh hold"}
}

// hookDecided records a hold decision. It turns the decision into
// an answer. An approval records the approval and the allowed
// call. A denial records the denial only.
func (px *Proxy) hookDecided(session, tool string, args json.RawMessage, res decisionResult, agentID string) hookDecision {
	if res.approved {
		if _, err := px.ledger.AppendDetailed(session, "approval", tool, args, "approve", res.actor, ledger.EventDetail{AgentID: agentID}); err != nil {
			return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		if _, err := px.ledger.AppendDetailed(session, "tool_call", tool, args, "allow", res.actor, ledger.EventDetail{AgentID: agentID}); err != nil {
			return hookDecision{Decision: "deny", Reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookDecision{Decision: "allow"}
	}
	if _, err := px.ledger.AppendDetailed(session, "approval", tool, args, "deny", res.actor, ledger.EventDetail{AgentID: agentID}); err != nil {
		log.Printf("ledger write failed on approval deny: %v", err)
	}
	return hookDecision{Decision: "deny", Reason: "ledgerline: tool call denied by approver"}
}
