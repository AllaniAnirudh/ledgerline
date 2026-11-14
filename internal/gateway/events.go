package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// eventsResponse is the shape of GET /v1/events. Events is
// always an array, never null. Total counts the filtered events
// before paging. Limit and offset echo the applied paging.
type eventsResponse struct {
	Events []ledger.Event `json:"events"`
	Total  int            `json:"total"`
	Limit  int            `json:"limit"`
	Offset int            `json:"offset"`
}

// serveEvents answers GET /v1/events. Filters are query params:
// session, tool, kind, decision, mode, from, to (RFC 3339).
// Paging is limit (default 100, max 500) and offset (default 0).
// The whole chain is loaded for the query. Filtering happens
// in memory. The chain is small in local mode. A large chain
// pays the full load on every query.
//
// The gateway param selects the source. Without it, events
// merge across the local gateway and all peers. The merged
// timeline sorts by timestamp. The answer says so with
// merged_by. Each event carries its gateway name. A peer that
// does not answer during a merge is named in unreachable. Its
// events are absent, not silent. With gateway=local only local
// events return. With gateway=<peer name> only that peer
// returns. An unknown name is a 404. A peer that does not
// answer a direct pull is a 502.
func (px *Proxy) serveEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var from, to time.Time
	var err error
	if v := q.Get("from"); v != "" {
		from, err = time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "from must be RFC 3339", http.StatusBadRequest)
			return
		}
	}
	if v := q.Get("to"); v != "" {
		to, err = time.Parse(time.RFC3339, v)
		if err != nil {
			http.Error(w, "to must be RFC 3339", http.StatusBadRequest)
			return
		}
	}
	limit := 100
	if v := q.Get("limit"); v != "" {
		limit, err = strconv.Atoi(v)
		if err != nil || limit < 0 {
			http.Error(w, "limit must be a number from 0 to 500", http.StatusBadRequest)
			return
		}
		if limit == 0 {
			limit = 100
		}
		if limit > 500 {
			limit = 500
		}
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		offset, err = strconv.Atoi(v)
		if err != nil || offset < 0 {
			http.Error(w, "offset must be a number from 0", http.StatusBadRequest)
			return
		}
	}
	f := eventFilter{
		session:  q.Get("session"),
		tool:     q.Get("tool"),
		kind:     q.Get("kind"),
		decision: q.Get("decision"),
		mode:     q.Get("mode"),
		from:     from,
		to:       to,
	}
	gateway := q.Get("gateway")
	visited := parseVisitedHeader(r)
	switch {
	case gateway == "" || gateway == "local":
		events, err := px.ledger.Events()
		if err != nil {
			http.Error(w, "ledger read failed", http.StatusInternalServerError)
			return
		}
		local := filterEvents(events, f)
		if gateway == "local" {
			rows := make([]gatewayEvent, 0, len(local))
			for _, e := range local {
				rows = append(rows, gatewayEvent{Event: e, Gateway: "local"})
			}
			writeJSON(w, pageGatewayEvents(rows, limit, offset, "", nil, nil, nil))
			return
		}
		merged, down, info := px.mergePeerEvents(peerFilterQuery(q), local, visited)
		writeJSON(w, pageGatewayEvents(merged, limit, offset, "timestamp", down, info.truncated, info.totals))
		return
	default:
		px.peersMu.RLock()
		var peer PeerConfig
		var found bool
		for i := range px.peers {
			if px.peers[i].Name == gateway {
				peer = px.peers[i]
				found = true
				break
			}
		}
		px.peersMu.RUnlock()
		if !found {
			http.Error(w, "unknown gateway "+gateway, http.StatusNotFound)
			return
		}
		// A peer already visited in this pull chain means a
		// cycle. Refuse it instead of pulling again.
		if visited[peer.URL] {
			http.Error(w, "peer pull cycle: peer "+gateway+" already visited", http.StatusLoopDetected)
			return
		}
		// The peer chain is verified here before its events
		// are trusted. Paging happens here, after the check.
		chain, _, err := px.fetchVerifiedPeerChain(peer, visited)
		if err != nil {
			if errors.Is(err, errPeerChainInvalid) {
				http.Error(w, "peer "+gateway+" chain did not verify: "+err.Error(), http.StatusBadGateway)
				return
			}
			http.Error(w, "peer "+gateway+" unreachable: "+err.Error(), http.StatusBadGateway)
			return
		}
		events := filterEvents(chain, f)
		rows := make([]gatewayEvent, 0, len(events))
		for _, e := range events {
			rows = append(rows, gatewayEvent{Event: e, Gateway: gateway})
		}
		writeJSON(w, pageGatewayEvents(rows, limit, offset, "", nil, nil, nil))
		return
	}
}

// eventFilter carries the parsed GET /v1/events filters.
type eventFilter struct {
	session  string
	tool     string
	kind     string
	decision string
	mode     string
	from     time.Time
	to       time.Time
}

// filterEvents applies the filters to one event list.
func filterEvents(events []ledger.Event, f eventFilter) []ledger.Event {
	filtered := make([]ledger.Event, 0, len(events))
	for _, e := range events {
		if f.session != "" && e.SessionID != f.session {
			continue
		}
		if f.tool != "" && e.Tool != f.tool {
			continue
		}
		if f.kind != "" && e.Kind != f.kind {
			continue
		}
		if f.decision != "" && e.Decision != f.decision {
			continue
		}
		if f.mode != "" && e.Mode != f.mode {
			continue
		}
		if !f.from.IsZero() && e.Timestamp.Before(f.from) {
			continue
		}
		if !f.to.IsZero() && e.Timestamp.After(f.to) {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// pageGatewayEvents pages a gateway-labelled list. MergedBy
// and down are set only on a merged answer. Truncated and
// totals carry the per peer cap detail of a merged answer.
func pageGatewayEvents(rows []gatewayEvent, limit, offset int, mergedBy string, down []string, truncated []string, totals map[string]int) mergedEventsResponse {
	total := len(rows)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := rows[offset:end]
	if page == nil {
		page = []gatewayEvent{}
	}
	return mergedEventsResponse{Events: page, Total: total, Limit: limit, Offset: offset, MergedBy: mergedBy, Unreachable: down, Truncated: truncated, PeerTotals: totals}
}

// sessionRow is one row of GET /v1/sessions. The group key is
// session_id. A row is a session, never an agent. Agent ids are
// listed only as ids seen on the session. They stay empty until
// proxy-path identity lands.
type sessionRow struct {
	SessionID  string   `json:"session_id"`
	TotalCalls int      `json:"total_calls"`
	Allowed    int      `json:"allowed_calls"`
	Denied     int      `json:"denied_calls"`
	Detected   int      `json:"detected"`
	Holds      int      `json:"holds"`
	Proposals  int      `json:"proposals"`
	Contained  int      `json:"containment_count"`
	FirstSeen  string   `json:"first_seen"`
	LastSeen   string   `json:"last_seen"`
	Status     string   `json:"status"`
	AgentIDs   []string `json:"agent_ids"`
}

// activeWindow decides the active status. A session with an
// event inside the window is active. Older sessions are idle.
// Contained sessions report contained regardless of age.
const activeWindow = 5 * time.Minute

// serveSessions answers GET /v1/sessions. It groups the chain
// by session_id and counts calls per session. Counts come from
// the ledger only. Containment status also reads the live list.
// Rows sort by session id, so the output is stable.
func (px *Proxy) serveSessions(w http.ResponseWriter, r *http.Request) {
	events, err := px.ledger.Events()
	if err != nil {
		http.Error(w, "ledger read failed", http.StatusInternalServerError)
		return
	}
	contained := map[string]bool{}
	for _, c := range px.ContainedList() {
		contained[c.SessionID] = true
	}
	rows := map[string]*sessionRow{}
	agents := map[string]map[string]bool{}
	for _, e := range events {
		row := rows[e.SessionID]
		if row == nil {
			row = &sessionRow{SessionID: e.SessionID}
			rows[e.SessionID] = row
			agents[e.SessionID] = map[string]bool{}
		}
		if e.AgentID != "" {
			agents[e.SessionID][e.AgentID] = true
		}
		if row.FirstSeen == "" || e.Timestamp.Format(time.RFC3339Nano) < row.FirstSeen {
			row.FirstSeen = e.Timestamp.Format(time.RFC3339Nano)
		}
		if e.Timestamp.Format(time.RFC3339Nano) > row.LastSeen {
			row.LastSeen = e.Timestamp.Format(time.RFC3339Nano)
		}
		switch e.Kind {
		case "tool_call":
			row.TotalCalls++
			if e.Decision == "allow" {
				row.Allowed++
			}
		case "policy_decision":
			if e.Mode == "detect" && isRestrictive(e.Decision) {
				row.Detected++
			} else if e.Decision == "deny" {
				row.Denied++
			}
		case "approval":
			switch e.Decision {
			case "hold":
				row.Holds++
			case "deny":
				row.Denied++
			}
		case "proposal":
			if e.Decision == "propose" {
				row.Proposals++
			}
		case "containment":
			row.Contained++
		}
	}
	out := make([]sessionRow, 0, len(rows))
	now := time.Now().UTC()
	for _, row := range rows {
		// System events carry no agent session. The tools
		// baseline and drift writers use an empty session.
		// Token revokes, policy changes, and upstream
		// re-approvals write under "gateway". Neither is an
		// agent session. The roster shows agent sessions only.
		if row.SessionID == "" || row.SessionID == "gateway" {
			continue
		}
		ids := make([]string, 0, len(agents[row.SessionID]))
		for id := range agents[row.SessionID] {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		row.AgentIDs = ids
		switch {
		case contained[row.SessionID]:
			row.Status = "contained"
		default:
			last, err := time.Parse(time.RFC3339Nano, row.LastSeen)
			if err == nil && now.Sub(last) <= activeWindow {
				row.Status = "active"
			} else {
				row.Status = "idle"
			}
		}
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SessionID < out[j].SessionID })
	writeJSON(w, out)
}

// isRestrictive reports whether a policy decision would have
// stopped or gated the call. Allow is not restrictive.
func isRestrictive(decision string) bool {
	switch decision {
	case "deny", "hold", "contain", "propose":
		return true
	}
	return false
}

// revokeRequest is the body of POST /v1/tokens/revoke.
type revokeRequest struct {
	JTI string `json:"jti"`
}

// serveTokensRevoke answers POST /v1/tokens/revoke. It records
// a token_revoked event in the ledger, then persists the jti.
// The actor is the approver name when a per-approver token was
// used. A revoked token is rejected from then on, across
// restarts. Revoking an unknown jti still succeeds. It is
// idempotent. A ledger failure refuses the revocation. The
// caller retries.
func (px *Proxy) serveTokensRevoke(w http.ResponseWriter, r *http.Request) {
	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad revoke body", http.StatusBadRequest)
		return
	}
	req.JTI = strings.TrimSpace(req.JTI)
	if req.JTI == "" {
		http.Error(w, "revoke needs a jti", http.StatusBadRequest)
		return
	}
	actor, _ := px.approverActor(r)
	args, _ := json.Marshal(map[string]string{"jti": req.JTI})
	if _, err := px.ledger.AppendDetailed("gateway", "token_revoked", "(token)", args, "revoke", actor, ledger.EventDetail{}); err != nil {
		http.Error(w, "ledger write failed", http.StatusInternalServerError)
		return
	}
	if err := px.RevokeToken(req.JTI); err != nil {
		http.Error(w, "revocation file write failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{"ok": true, "jti": req.JTI})
}
