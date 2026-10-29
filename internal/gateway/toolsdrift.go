package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// Tools-drift detection, after the compromised-MCP-server threat in
// Replit's architecture paper: an upstream that gains a tool
// mid-run is not the upstream the human approved. The gateway
// records the tool surface it first sees as the baseline, the
// trust anchor, and enforces it from then on.
//
// Semantics, stated exactly because they are the whole feature:
//
//   - The baseline is established from the first tools/list the
//     gateway can read: the startup probe when the upstream
//     answers it, otherwise the first tools/list response passing
//     through. The first sighting is trusted (TOFU), exactly like
//     the upstream pin's first run.
//   - The baseline survives restarts: it is stored in the ledger
//     store, so a restart does not grant the upstream amnesty. In
//     in-memory mode it lives only while the process lives.
//   - Enforcement denies unknown tool NAMES only: a tools/call
//     for a name outside the baseline is denied until a human
//     accepts the new surface. Removals and description/schema
//     changes are witnessed as drift but do not block calls to
//     baseline tools: a partial or transient list must not break
//     tools the human already trusts.
//   - Acceptance is explicit and witnessed: --reapprove-tools at
//     startup, or POST /v1/tools/accept, makes the NEXT observed
//     list the new baseline. There is no silent re-baselining.
//     Acceptance is only as trustworthy as the control-plane
//     token: with no --api-token and no per-approver tokens, the
//     accept endpoint is open to anyone who can reach the port,
//     including the agent itself, so drift enforcement in that
//     configuration is a tripwire for a human watching the
//     ledger, not a boundary the agent cannot cross. The
//     gateway logs a warning at startup in that case, and the
//     drift docs carry the same caveat.
//   - Pagination is never a surface: a tools/list page carrying
//     nextCursor is one page, not the whole list. The probe
//     follows cursors to build the full baseline, and a partial
//     page passing through is ignored for baseline purposes, so
//     page-2 tools are never denied as drift.
//   - A tools/list response the gateway cannot parse (including
//     an SSE stream it cannot decode) changes nothing: no
//     baseline, no drift event, no enforcement change. SSE
//     payloads split across several data lines are joined before
//     parsing, then each line is tried alone.
//   - With no baseline at all, everything is allowed: there is
//     nothing to drift from yet.

func isToolsList(body []byte) bool {
	var m jsonRPC
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	return m.Method == "tools/list"
}

type listTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

type listResult struct {
	Tools      []listTool `json:"tools"`
	NextCursor string     `json:"nextCursor"`
}

type listResponse struct {
	Result listResult `json:"result"`
}

// parseToolsList extracts the tool surface from a tools/list
// response body, plus the pagination cursor when the response is
// one page of many ("" means a complete surface). It accepts a
// plain JSON body, and, failing that, the data payloads of an SSE
// stream: payloads split across several data lines are joined
// first, then each line is tried alone. It returns false when
// nothing parses.
func parseToolsList(body []byte) (ledger.ToolsBaseline, string, bool) {
	if b, cursor, ok := parseToolsListJSON(body); ok {
		return b, cursor, true
	}
	var data []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data = append(data, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
	}
	if len(data) > 0 {
		if b, cursor, ok := parseToolsListJSON([]byte(strings.Join(data, "\n"))); ok {
			return b, cursor, true
		}
		for _, d := range data {
			if b, cursor, ok := parseToolsListJSON([]byte(d)); ok {
				return b, cursor, true
			}
		}
	}
	return ledger.ToolsBaseline{}, "", false
}

func parseToolsListJSON(body []byte) (ledger.ToolsBaseline, string, bool) {
	var resp listResponse
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result.Tools == nil {
		return ledger.ToolsBaseline{}, "", false
	}
	tools := make([]ledger.BaselineTool, 0, len(resp.Result.Tools))
	for _, t := range resp.Result.Tools {
		if t.Name == "" {
			continue
		}
		tools = append(tools, ledger.BaselineTool{Name: t.Name, Description: t.Description, Schema: canonicalSchema(t.InputSchema)})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	return ledger.ToolsBaseline{Tools: tools, Hash: hashTools(tools)}, resp.Result.NextCursor, true
}

// canonicalSchema canonicalizes an inputSchema the way the
// baseline hash needs it: key order must not matter, or a server
// that serializes the same schema with keys in a different order
// reports phantom drift on every list. encoding/json sorts map
// keys on marshal; UseNumber keeps number literals intact. This
// is baseline-only: the ledger chain keeps its own compacting
// canonical form, which must never change.
func canonicalSchema(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return canonicalArgs(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return canonicalArgs(raw)
	}
	return string(out)
}

// hashTools identifies a surface: tools sorted by name, then
// description, then schema, so duplicate names hash
// deterministically instead of wobbling with input order.
func hashTools(tools []ledger.BaselineTool) string {
	sorted := append([]ledger.BaselineTool(nil), tools...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		if sorted[i].Description != sorted[j].Description {
			return sorted[i].Description < sorted[j].Description
		}
		return sorted[i].Schema < sorted[j].Schema
	})
	var buf bytes.Buffer
	for _, t := range sorted {
		buf.WriteString(t.Name)
		buf.WriteByte(0)
		buf.WriteString(t.Description)
		buf.WriteByte(0)
		buf.WriteString(t.Schema)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return hex.EncodeToString(sum[:])
}

// diffTools compares an old surface with a new one: names present
// only in the new surface, names missing from it, and names
// present in both with a changed description or schema.
func diffTools(old, new []ledger.BaselineTool) (added, removed, changed []string) {
	added = []string{}
	removed = []string{}
	changed = []string{}
	oldByName := map[string]ledger.BaselineTool{}
	for _, t := range old {
		oldByName[t.Name] = t
	}
	newByName := map[string]ledger.BaselineTool{}
	for _, t := range new {
		newByName[t.Name] = t
	}
	for _, t := range new {
		if prev, ok := oldByName[t.Name]; !ok {
			added = append(added, t.Name)
		} else if prev.Description != t.Description || prev.Schema != t.Schema {
			changed = append(changed, t.Name)
		}
	}
	for _, t := range old {
		if _, ok := newByName[t.Name]; !ok {
			removed = append(removed, t.Name)
		}
	}
	return added, removed, changed
}

func hashArgs(hash string) json.RawMessage {
	raw, _ := json.Marshal(map[string]string{"hash": hash})
	return raw
}

func driftArgs(added, removed, changed []string, baselineHash string) json.RawMessage {
	raw, _ := json.Marshal(map[string]any{"added": added, "removed": removed, "changed": changed, "baseline_hash": baselineHash})
	return raw
}

func toolNames(tools []ledger.BaselineTool) []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}

// loadToolsBaseline restores the stored baseline at startup, so a
// restart does not reset the trust anchor.
func (px *Proxy) loadToolsBaseline() error {
	b, found, err := px.ledger.ToolsBaselineGet()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	// Recompute the hash from the stored tools: the hash function
	// is baseline-only, so a row written by an older build may
	// carry a hash in the old form. Recomputing heals it silently
	// instead of reporting phantom drift on the first list after
	// an upgrade.
	b.Hash = hashTools(b.Tools)
	px.toolsBaseline = &b
	cp := b
	px.toolsLatest = &cp
	return nil
}

// toolsGate reports whether a tool call must be denied as drift:
// the baseline exists and the name is outside it. The denial
// names what changed, so the human can decide from the error
// alone without a second command: a tool the gateway has seen
// appear since the baseline is listed as added, while a name
// never seen in any list stays a plain unknown.
func (px *Proxy) toolsGate(tool string) (string, bool) {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	if px.toolsBaseline == nil {
		return "", false
	}
	for _, t := range px.toolsBaseline.Tools {
		if t.Name == tool {
			return "", false
		}
	}
	msg := "ledgerline: tool not in baseline (drift): accept the new tool surface first (ledgerline accept-tools)"
	if px.toolsLatest != nil && px.toolsLatest.Hash != px.toolsBaseline.Hash {
		added, _, _ := diffTools(px.toolsBaseline.Tools, px.toolsLatest.Tools)
		for _, name := range added {
			if name == tool {
				msg = "ledgerline: tool not in baseline (drift): " + tool + " appeared after the baseline; added since baseline: " + strings.Join(added, ", ") + "; accept the new tool surface first (ledgerline accept-tools)"
				break
			}
		}
	}
	return msg, true
}

// SetToolsReapprovePending marks the next observed list as the new
// baseline, for --reapprove-tools and POST /v1/tools/accept.
func (px *Proxy) SetToolsReapprovePending(actor string) {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	px.toolsReapprovePending = true
	px.toolsReapproveActor = actor
}

// applyToolsList folds one observed surface into the baseline
// state: establish, reapprove, drift, or no change. It witnesses
// every transition except no-change, and persists baseline moves.
// Callers hold no lock; this takes toolsMu. The in-memory anchor
// moves before the ledger writes, so a failing write restores
// the previous state instead of leaving a move the chain never
// saw. Witness args carry the baseline hash, so the chain shows
// what surface was trusted when; the baseline row itself is not
// covered by chain verification (see SECURITY.md).
func (px *Proxy) applyToolsList(observed ledger.ToolsBaseline, actor string) error {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	now := time.Now().UTC()
	observed.CreatedAt = now
	observed.UpdatedAt = now
	prevBaseline, prevLatest := px.toolsBaseline, px.toolsLatest
	prevPending, prevActor := px.toolsReapprovePending, px.toolsReapproveActor
	restore := func() {
		px.toolsBaseline, px.toolsLatest = prevBaseline, prevLatest
		px.toolsReapprovePending, px.toolsReapproveActor = prevPending, prevActor
	}
	switch {
	case px.toolsBaseline == nil:
		// Establishment wins over a pending re-approval: there
		// is no earlier baseline to re-approve, so a first list
		// witnesses "establish" and consumes the pending flag.
		px.toolsReapprovePending = false
		px.toolsBaseline = &observed
		cp := observed
		px.toolsLatest = &cp
		if err := px.ledger.ToolsBaselinePut(observed); err != nil {
			restore()
			return err
		}
		if _, err := px.ledger.Append("", "tools_baseline", "", hashArgs(observed.Hash), "establish", actor); err != nil {
			restore()
			return err
		}
	case px.toolsReapprovePending:
		px.toolsReapprovePending = false
		actor = px.toolsReapproveActor
		px.toolsBaseline = &observed
		cp := observed
		px.toolsLatest = &cp
		if err := px.ledger.ToolsBaselinePut(observed); err != nil {
			restore()
			return err
		}
		if _, err := px.ledger.Append("", "tools_baseline", "", hashArgs(observed.Hash), "reapprove", actor); err != nil {
			restore()
			return err
		}
	case px.toolsBaseline.Hash == observed.Hash:
		cp := observed
		px.toolsLatest = &cp
	default:
		added, removed, changed := diffTools(px.toolsBaseline.Tools, observed.Tools)
		anchor := px.toolsBaseline.Hash
		cp := observed
		px.toolsLatest = &cp
		if _, err := px.ledger.Append("", "tools_drift", "", driftArgs(added, removed, changed, anchor), "drift", actor); err != nil {
			restore()
			return err
		}
	}
	return nil
}

// HasToolsBaseline reports whether a trust anchor exists yet.
func (px *Proxy) HasToolsBaseline() bool {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	return px.toolsBaseline != nil
}

// ProbeToolsBaseline asks the upstream for its tool surface at
// startup. A network or parse failure is not fatal: the first
// tools/list passing through will establish the baseline instead,
// and runGateway retries quietly until one exists. A store or
// witness failure is fatal, like any ledger failure.
// The probe carries brokered headers, since the upstream may need
// them, and its body is redacted before parsing so the baseline
// hash matches what passthrough observations compute.
func (px *Proxy) ProbeToolsBaseline() error {
	return px.probeToolsBaseline(false)
}

// ProbeToolsBaselineQuiet is the retry-loop probe: same work, no
// per-failure log lines.
func (px *Proxy) ProbeToolsBaselineQuiet() error {
	return px.probeToolsBaseline(true)
}

func (px *Proxy) probeToolsBaseline(quiet bool) error {
	note := func(msg string) {
		if !quiet {
			log.Printf("tools baseline probe: %s", msg)
		}
	}
	// Follow pagination cursors: the baseline is the whole
	// surface, not page 1 of it.
	var all []ledger.BaselineTool
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		paramsJSON, _ := json.Marshal(params)
		body := []byte(`{"jsonrpc":"2.0","id":"ledgerline-baseline","method":"tools/list","params":` + string(paramsJSON) + `}`)
		req, err := http.NewRequest(http.MethodPost, px.upstream.String(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if px.broker != nil {
			px.broker.InjectHeaders(req.Header)
		}
		// The probe has its own timeout: a hung upstream must
		// not hang gateway startup. Forwarding keeps its
		// no-timeout posture for long-lived streams.
		resp, err := px.probeClient.Do(req)
		if err != nil {
			note("upstream unreachable, baseline deferred to first tools/list")
			return nil
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
		resp.Body.Close()
		if err != nil || len(raw) > maxBodyBytes {
			note("unreadable response, baseline deferred to first tools/list")
			return nil
		}
		if px.broker != nil {
			raw = []byte(px.broker.RedactString(string(raw)))
		}
		observed, next, ok := parseToolsList(raw)
		if !ok {
			note("tools/list did not parse, baseline deferred to first tools/list")
			return nil
		}
		all = append(all, observed.Tools...)
		if next == "" {
			break
		}
		cursor = next
		if page == 99 {
			note("too many pages, baseline deferred to first tools/list")
			return nil
		}
	}
	combined := ledger.ToolsBaseline{Tools: all, Hash: hashTools(all)}
	sort.Slice(combined.Tools, func(i, j int) bool { return combined.Tools[i].Name < combined.Tools[j].Name })
	// applyToolsList itself decides establish, reapprove (when a
	// re-approval is pending), drift, or no change.
	return px.applyToolsList(combined, "gateway")
}

// observeToolsList folds a tools/list response that passed through
// the proxy into the baseline state. Unparseable, oversize, or
// paginated (partial-page) responses change nothing: a partial
// page is not a surface, and treating it as one would deny
// page-2 tools as drift.
func (px *Proxy) observeToolsList(raw []byte) {
	observed, cursor, ok := parseToolsList(raw)
	if !ok {
		return
	}
	if cursor != "" {
		log.Printf("tools/list page ignored for baseline: paginated response, next page not fetched")
		return
	}
	if err := px.applyToolsList(observed, "gateway"); err != nil {
		log.Printf("tools baseline update failed: %v", err)
	}
}

// serveToolsStatus answers GET /v1/tools: baseline, latest
// observed surface, whether they differ, and the drift detail.
func (px *Proxy) serveToolsStatus(w http.ResponseWriter, r *http.Request) {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	var baseline, latest any
	drift := false
	var detail any
	if px.toolsBaseline != nil {
		baseline = map[string]any{"hash": px.toolsBaseline.Hash, "tools": toolNames(px.toolsBaseline.Tools)}
	}
	if px.toolsLatest != nil {
		latest = map[string]any{"hash": px.toolsLatest.Hash, "tools": toolNames(px.toolsLatest.Tools)}
	}
	if px.toolsBaseline != nil && px.toolsLatest != nil && px.toolsBaseline.Hash != px.toolsLatest.Hash {
		drift = true
		added, removed, changed := diffTools(px.toolsBaseline.Tools, px.toolsLatest.Tools)
		detail = map[string][]string{"added": added, "removed": removed, "changed": changed}
	}
	writeJSON(w, map[string]any{
		"baseline": baseline, "latest": latest, "drift": drift,
		"drift_detail": detail, "pending_reapprove": px.toolsReapprovePending,
	})
}

// serveToolsAccept marks the next observed list as the new
// baseline. It does not itself change the baseline: the next list
// is what the human is accepting, after review.
func (px *Proxy) serveToolsAccept(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actor string `json:"actor"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		http.Error(w, "bad accept body", http.StatusBadRequest)
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
	px.SetToolsReapprovePending(actor)
	writeJSON(w, map[string]any{"pending": true})
}
