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
//   - A tools/list response the gateway cannot parse (including
//     an SSE stream it cannot decode) changes nothing: no
//     baseline, no drift event, no enforcement change.
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
	Tools []listTool `json:"tools"`
}

type listResponse struct {
	Result listResult `json:"result"`
}

// parseToolsList extracts the tool surface from a tools/list
// response body. It accepts a plain JSON body, and, failing that,
// the data payloads of an SSE stream (each data line tried as a
// JSON-RPC response). It returns false when nothing parses.
func parseToolsList(body []byte) (ledger.ToolsBaseline, bool) {
	if b, ok := parseToolsListJSON(body); ok {
		return b, true
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		if b, ok := parseToolsListJSON([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data:")))); ok {
			return b, true
		}
	}
	return ledger.ToolsBaseline{}, false
}

func parseToolsListJSON(body []byte) (ledger.ToolsBaseline, bool) {
	var resp listResponse
	if err := json.Unmarshal(body, &resp); err != nil || resp.Result.Tools == nil {
		return ledger.ToolsBaseline{}, false
	}
	tools := make([]ledger.BaselineTool, 0, len(resp.Result.Tools))
	for _, t := range resp.Result.Tools {
		if t.Name == "" {
			continue
		}
		tools = append(tools, ledger.BaselineTool{Name: t.Name, Description: t.Description, Schema: canonicalArgs(t.InputSchema)})
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	var buf bytes.Buffer
	for _, t := range tools {
		buf.WriteString(t.Name)
		buf.WriteByte(0)
		buf.WriteString(t.Description)
		buf.WriteByte(0)
		buf.WriteString(t.Schema)
		buf.WriteByte('\n')
	}
	sum := sha256.Sum256(buf.Bytes())
	return ledger.ToolsBaseline{Tools: tools, Hash: hex.EncodeToString(sum[:])}, true
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

func driftArgs(added, removed, changed []string) json.RawMessage {
	raw, _ := json.Marshal(map[string][]string{"added": added, "removed": removed, "changed": changed})
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
// Callers hold no lock; this takes toolsMu.
func (px *Proxy) applyToolsList(observed ledger.ToolsBaseline, actor string) error {
	px.toolsMu.Lock()
	defer px.toolsMu.Unlock()
	now := time.Now().UTC()
	observed.CreatedAt = now
	observed.UpdatedAt = now
	switch {
	case px.toolsReapprovePending:
		px.toolsReapprovePending = false
		actor = px.toolsReapproveActor
		px.toolsBaseline = &observed
		cp := observed
		px.toolsLatest = &cp
		if err := px.ledger.ToolsBaselinePut(observed); err != nil {
			return err
		}
		if _, err := px.ledger.Append("", "tools_baseline", "", nil, "reapprove", actor); err != nil {
			return err
		}
	case px.toolsBaseline == nil:
		px.toolsBaseline = &observed
		cp := observed
		px.toolsLatest = &cp
		if err := px.ledger.ToolsBaselinePut(observed); err != nil {
			return err
		}
		if _, err := px.ledger.Append("", "tools_baseline", "", nil, "establish", actor); err != nil {
			return err
		}
	case px.toolsBaseline.Hash == observed.Hash:
		cp := observed
		px.toolsLatest = &cp
	default:
		added, removed, changed := diffTools(px.toolsBaseline.Tools, observed.Tools)
		cp := observed
		px.toolsLatest = &cp
		if _, err := px.ledger.Append("", "tools_drift", "", driftArgs(added, removed, changed), "drift", actor); err != nil {
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
	body := []byte(`{"jsonrpc":"2.0","id":"ledgerline-baseline","method":"tools/list","params":{}}`)
	req, err := http.NewRequest(http.MethodPost, px.upstream.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if px.broker != nil {
		px.broker.InjectHeaders(req.Header)
	}
	resp, err := px.client.Do(req)
	if err != nil {
		note("upstream unreachable, baseline deferred to first tools/list")
		return nil
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil || len(raw) > maxBodyBytes {
		note("unreadable response, baseline deferred to first tools/list")
		return nil
	}
	if px.broker != nil {
		raw = []byte(px.broker.RedactString(string(raw)))
	}
	observed, ok := parseToolsList(raw)
	if !ok {
		note("tools/list did not parse, baseline deferred to first tools/list")
		return nil
	}
	// applyToolsList itself decides establish, reapprove (when a
	// re-approval is pending), drift, or no change.
	return px.applyToolsList(observed, "gateway")
}

// observeToolsList folds a tools/list response that passed through
// the proxy into the baseline state. Unparseable or oversize
// responses change nothing.
func (px *Proxy) observeToolsList(raw []byte) {
	observed, ok := parseToolsList(raw)
	if !ok {
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
	_ = json.NewDecoder(r.Body).Decode(&req)
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
