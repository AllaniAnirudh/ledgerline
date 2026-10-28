package gateway

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// containedSession is one frozen session: every further call from it
// is denied, and its pending held calls were denied when it froze.
type containedSession struct {
	SessionID   string    `json:"session_id"`
	Actor       string    `json:"actor,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	ContainedAt time.Time `json:"contained_at"`
}

// Contain freezes a session: it is marked contained, its pending held
// calls are denied, and the freeze is witnessed in the ledger. The
// session stays contained even if the ledger write fails: containment
// denies passage, so keeping it is the fail-closed direction, and
// the failure is logged loudly.
func (px *Proxy) Contain(sessionID, actor, reason string) {
	px.containedMu.Lock()
	if px.contained == nil {
		px.contained = map[string]containedSession{}
	}
	px.contained[sessionID] = containedSession{
		SessionID:   sessionID,
		Actor:       actor,
		Reason:      reason,
		ContainedAt: time.Now().UTC(),
	}
	px.containedMu.Unlock()

	denied := px.approvals.DenySession(sessionID, actor)
	if _, err := px.ledger.Append(sessionID, "containment", "(session)", nil, "contain", actor); err != nil {
		log.Printf("ledgerline: ledger write failed on containment of session %s: %v", sessionID, err)
	}
	log.Printf("ledgerline: session %s contained by %s (%s); %d held calls denied", sessionID, actor, reason, denied)
}

// containRequest is the body of POST /v1/sessions/{id}/contain.
type containRequest struct {
	Actor  string `json:"actor"`
	Reason string `json:"reason"`
}

// containSessionAPI freezes one session from the control plane. The
// actor rule matches decideApproval: a caller authenticated with a
// per-approver token is recorded under the bound name, and a body
// name that disagrees with the credential is rejected.
func (px *Proxy) containSessionAPI(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/sessions/"), "/contain")
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

// IsContained reports whether a session is frozen.
func (px *Proxy) IsContained(sessionID string) bool {
	px.containedMu.Lock()
	defer px.containedMu.Unlock()
	_, ok := px.contained[sessionID]
	return ok
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
