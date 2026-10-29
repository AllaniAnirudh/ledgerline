package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// containedSession is one frozen session. Every further call from
// it is denied. Its pending held calls were denied when it froze.
type containedSession struct {
	SessionID   string    `json:"session_id"`
	Actor       string    `json:"actor,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	ContainedAt time.Time `json:"contained_at"`
}

// observeMCP records that an upstream MCP session id was seen on a
// ledger session. A later containment of that ledger session then
// freezes the MCP session too.
func (px *Proxy) observeMCP(sessionID, mcpID string) {
	if mcpID == "" {
		return
	}
	px.containedMu.Lock()
	defer px.containedMu.Unlock()
	if px.observed == nil {
		px.observed = map[string]map[string]bool{}
	}
	set := px.observed[sessionID]
	if set == nil {
		set = map[string]bool{}
		px.observed[sessionID] = set
	}
	set[mcpID] = true
}

// Contain freezes a session. It is marked contained. Every
// upstream MCP session observed on it is frozen too. Its pending
// held calls are denied. Its in-flight upstream requests are
// cancelled gateway-side (see forward for the exact guarantee).
// The freeze is witnessed in the ledger, with the frozen MCP
// sessions in the event arguments. The session stays contained
// even if the ledger write fails. Containment denies passage,
// so keeping it is the fail-closed direction. The failure is
// logged loudly.
func (px *Proxy) Contain(sessionID, actor, reason string) {
	px.containedMu.Lock()
	if px.contained == nil {
		px.contained = map[string]containedSession{}
	}
	if px.containedMCP == nil {
		px.containedMCP = map[string]bool{}
	}
	px.contained[sessionID] = containedSession{
		SessionID:   sessionID,
		Actor:       actor,
		Reason:      reason,
		ContainedAt: time.Now().UTC(),
	}
	var mcpIDs []string
	for id := range px.observed[sessionID] {
		px.containedMCP[id] = true
		mcpIDs = append(mcpIDs, id)
	}
	px.containedMu.Unlock()

	denied := px.approvals.DenySession(sessionID, actor)
	px.cancelInflight(sessionID)
	var args json.RawMessage
	if len(mcpIDs) > 0 {
		args, _ = json.Marshal(map[string][]string{"mcp_sessions": mcpIDs})
	}
	if _, err := px.ledger.Append(sessionID, "containment", "(session)", args, "contain", actor); err != nil {
		log.Printf("ledgerline: ledger write failed on containment of session %s: %v", sessionID, err)
	}
	if sessionID == "default" {
		log.Printf("ledgerline: WARNING: containing the shared default session blocks every headerless client")
	}
	log.Printf("ledgerline: session %s contained by %s (%s); %d held calls denied", sessionID, actor, reason, denied)
}

// containRequest is the body of POST /v1/sessions/{id}/contain.
type containRequest struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// containSessionAPI freezes one session from the control plane.
// The actor rule matches decideApproval. A caller authenticated
// with a per-approver token is recorded under the bound name.
// A body name that disagrees with the credential is rejected.
func (px *Proxy) containSessionAPI(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/contain")
	// The CLI escapes the id. Unescape it here so session ids
	// containing ?, #, or % route to the session they name.
	if unescaped, err := url.PathUnescape(id); err == nil {
		id = unescaped
	}
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	var req containRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}
	actor := req.Actor
	if name, bound := px.approverActor(r); bound {
		if actor != "" && actor != name {
			http.Error(w, "actor does not match the approver token", http.StatusForbidden)
			return
		}
		actor = name
	}
	px.Contain(id, actor, req.Reason)
	writeJSON(w, map[string]any{"ok": true, "session_id": id})
}

// IsContained reports whether a ledger session or an upstream MCP
// session id is frozen.
func (px *Proxy) IsContained(sessionID, mcpID string) bool {
	px.containedMu.Lock()
	defer px.containedMu.Unlock()
	if _, ok := px.contained[sessionID]; ok {
		return true
	}
	if mcpID != "" {
		if _, ok := px.containedMCP[mcpID]; ok {
			return true
		}
	}
	return false
}

// ContainedList returns a snapshot of frozen sessions.
func (px *Proxy) ContainedList() []containedSession {
	px.containedMu.Lock()
	defer px.containedMu.Unlock()
	out := make([]containedSession, 0, len(px.contained))
	for _, c := range px.contained {
		out = append(out, c)
	}
	return out
}
