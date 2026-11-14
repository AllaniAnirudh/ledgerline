package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

const phaseCPolicyYAML = `version: 1
default: allow
rules:
  - tool: exec
    action: deny
    reason: "shell is off limits"
  - tool: write_file
    action: hold
    mode: detect
    reason: "writes are watched"
`

// policyFileProxy builds a proxy from a policy file on disk. It
// wires the modes path like the gateway command does. It sets
// the control-plane token to "s3cret".
func policyFileProxy(t *testing.T, yaml string) (*Proxy, string, string) {
	t.Helper()
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	modesPath := policyPath + ".modes.json"
	b, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	modes, err := policy.LoadModeOverrides(modesPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.ParseWithOverrides(b, modes)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)
	px, err := New(upstream.URL, ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)
	px.SetAPIToken("s3cret")
	px.SetPolicySource(policyPath, b, modesPath, modes)
	return px, policyPath, modesPath
}

// postAPI posts a JSON body to the control plane and returns
// the status code and body. Token is the X-Ledgerline-Token
// header value. Empty token sends no header.
func postAPI(t *testing.T, px *Proxy, path, body, token string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Ledgerline-Token", token)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

// fakePeer serves /v1/verify and /v1/events for one peer. It
// checks the control token when wantToken is set. Events are
// returned in the order given, paged by limit and offset.
func fakePeer(t *testing.T, wantToken string, verifyOK bool, verifyErr string, events []ledger.Event) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantToken != "" && r.Header.Get("X-Ledgerline-Token") != wantToken {
			http.Error(w, "ledgerline: missing or bad API token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/verify":
			writeJSON(w, map[string]any{"ok": verifyOK, "error": verifyErr})
		case "/v1/events":
			q := r.URL.Query()
			limit := 100
			if v := q.Get("limit"); v != "" {
				limit, _ = strconv.Atoi(v)
			}
			offset := 0
			if v := q.Get("offset"); v != "" {
				offset, _ = strconv.Atoi(v)
			}
			total := len(events)
			if offset > total {
				offset = total
			}
			end := offset + limit
			if end > total {
				end = total
			}
			out := events[offset:end]
			if out == nil {
				out = []ledger.Event{}
			}
			writeJSON(w, map[string]any{"events": out, "total": total, "limit": limit, "offset": offset})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func peerEvent(seq uint64, at time.Time, tool, decision string) ledger.Event {
	return ledger.Event{Seq: seq, Timestamp: at, SessionID: "peer-session", Kind: "tool_call", Tool: tool, Decision: decision}
}

func TestLoadPeersFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peers.json")
	body := `[{"name":"a","url":"http://localhost:9001","token":"tok"}]`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPeersFile(path); err == nil {
		t.Fatal("a group- or world-readable peers file must be refused")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	peers, err := LoadPeersFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Name != "a" {
		t.Fatalf("peers = %+v", peers)
	}
	// Duplicate names fail.
	dup := filepath.Join(dir, "dup.json")
	if err := os.WriteFile(dup, []byte(`[{"name":"a","url":"http://localhost:1"},{"name":"a","url":"http://localhost:2"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPeersFile(dup); err == nil {
		t.Fatal("duplicate peer names must fail")
	}
	// "local" is reserved.
	reserved := filepath.Join(dir, "reserved.json")
	if err := os.WriteFile(reserved, []byte(`[{"name":"local","url":"http://localhost:1"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPeersFile(reserved); err == nil {
		t.Fatal("peer name local must fail")
	}
	// A bad URL fails.
	badURL := filepath.Join(dir, "badurl.json")
	if err := os.WriteFile(badURL, []byte(`[{"name":"a","url":"not-a-url"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPeersFile(badURL); err == nil {
		t.Fatal("a bad peer url must fail")
	}
}

func TestPeersCoverageRows(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	postTool(t, px, "read_file")
	postTool(t, px, "exec")

	now := time.Now().UTC()
	up := fakePeer(t, "peer-tok", true, "", []ledger.Event{
		peerEvent(0, now.Add(-time.Hour), "read_file", "allow"),
		peerEvent(1, now, "read_file", "allow"),
		peerEvent(2, now.Add(time.Hour), "read_file", "allow"),
	})
	broken := fakePeer(t, "", false, "chain broken at seq 4", []ledger.Event{
		peerEvent(0, now, "read_file", "allow"),
	})
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	downURL := down.URL
	down.Close()

	px.SetPeers([]PeerConfig{
		{Name: "up", URL: up.URL, Token: "peer-tok"},
		{Name: "broken", URL: broken.URL},
		{Name: "down", URL: downURL},
	})

	code, raw := getAPI(t, px, "/v1/peers")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/peers: want 200, got %d (%s)", code, raw)
	}
	var rows []peerStatus
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("want 4 rows (local + 3 peers), got %+v", rows)
	}
	byName := map[string]peerStatus{}
	for _, r := range rows {
		byName[r.Name] = r
	}
	local := byName["local"]
	if !local.Reachable || !local.ChainOK || local.EventCount != 3 {
		t.Fatalf("local row: want reachable chain ok count 3, got %+v", local)
	}
	if local.LastSync == "" {
		t.Fatal("local row needs a last sync time")
	}
	upRow := byName["up"]
	if !upRow.Reachable || !upRow.ChainOK || upRow.EventCount != 3 {
		t.Fatalf("up row: want reachable chain ok count 3, got %+v", upRow)
	}
	if upRow.LastSync == "" {
		t.Fatal("up row needs a last sync time")
	}
	brokenRow := byName["broken"]
	if !brokenRow.Reachable || brokenRow.ChainOK || brokenRow.ChainError != "chain broken at seq 4" {
		t.Fatalf("broken row: want reachable with chain failure, got %+v", brokenRow)
	}
	downRow := byName["down"]
	if downRow.Reachable || downRow.Error == "" {
		t.Fatalf("down row: want unreachable with error text, got %+v", downRow)
	}
	// Peers sit behind the control-plane token.
	req := httptest.NewRequest(http.MethodGet, "/v1/peers", nil)
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no control token: want 401, got %d", rec.Code)
	}
}

func TestMergedEvents(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	postTool(t, px, "read_file") // local allow, timestamp near now
	postTool(t, px, "exec")      // local deny, timestamp near now

	now := time.Now().UTC()
	up := fakePeer(t, "", true, "", []ledger.Event{
		peerEvent(0, now.Add(-2*time.Hour), "old_tool", "allow"),
		peerEvent(1, now.Add(2*time.Hour), "new_tool", "allow"),
	})
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	downURL := down.URL
	down.Close()
	px.SetPeers([]PeerConfig{
		{Name: "up", URL: up.URL},
		{Name: "down", URL: downURL},
	})

	type resp struct {
		Events      []gatewayEvent `json:"events"`
		Total       int            `json:"total"`
		Limit       int            `json:"limit"`
		Offset      int            `json:"offset"`
		MergedBy    string         `json:"merged_by"`
		Unreachable []string       `json:"unreachable"`
	}
	get := func(path string) (int, resp) {
		t.Helper()
		code, raw := getAPI(t, px, path)
		var r resp
		_ = json.Unmarshal(raw, &r)
		return code, r
	}

	// Merged: local 3 events plus 2 peer events. The down peer
	// is named, not silent.
	code, r := get("/v1/events")
	if code != http.StatusOK {
		t.Fatalf("merged: want 200, got %d", code)
	}
	if r.MergedBy != "timestamp" {
		t.Fatalf("merged_by = %q, want timestamp", r.MergedBy)
	}
	if r.Total != 5 || len(r.Events) != 5 {
		t.Fatalf("merged: want total 5, got %+v", r)
	}
	if len(r.Unreachable) != 1 || r.Unreachable[0] != "down" {
		t.Fatalf("unreachable = %v, want [down]", r.Unreachable)
	}
	for i := 1; i < len(r.Events); i++ {
		if r.Events[i].Timestamp.Before(r.Events[i-1].Timestamp) {
			t.Fatalf("merged timeline is not sorted by timestamp: %+v", r.Events)
		}
	}
	if r.Events[0].Gateway != "up" || r.Events[0].Tool != "old_tool" {
		t.Fatalf("first merged row should be the old peer event, got %+v", r.Events[0])
	}
	if r.Events[len(r.Events)-1].Gateway != "up" || r.Events[len(r.Events)-1].Tool != "new_tool" {
		t.Fatalf("last merged row should be the new peer event, got %+v", r.Events[len(r.Events)-1])
	}
	seen := map[string]bool{}
	for _, e := range r.Events {
		seen[e.Gateway] = true
	}
	if !seen["local"] || !seen["up"] {
		t.Fatalf("merged rows must carry both gateway names, got %v", seen)
	}

	// Local only.
	_, r = get("/v1/events?gateway=local")
	if r.Total != 3 || r.MergedBy != "" {
		t.Fatalf("local filter: want total 3 with no merged_by, got %+v", r)
	}
	for _, e := range r.Events {
		if e.Gateway != "local" {
			t.Fatalf("local filter row has gateway %q", e.Gateway)
		}
	}

	// One peer only.
	_, r = get("/v1/events?gateway=up")
	if r.Total != 2 || len(r.Events) != 2 {
		t.Fatalf("peer filter: want total 2, got %+v", r)
	}
	for _, e := range r.Events {
		if e.Gateway != "up" {
			t.Fatalf("peer filter row has gateway %q", e.Gateway)
		}
	}

	// Unknown gateway is a 404.
	code, _ = get("/v1/events?gateway=nope")
	if code != http.StatusNotFound {
		t.Fatalf("unknown gateway: want 404, got %d", code)
	}
	// A down peer pulled direct is a 502.
	code, _ = get("/v1/events?gateway=down")
	if code != http.StatusBadGateway {
		t.Fatalf("down gateway: want 502, got %d", code)
	}
}

func TestPolicyListing(t *testing.T) {
	px, _, _ := policyFileProxy(t, phaseCPolicyYAML)
	code, raw := getAPI(t, px, "/v1/policy")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/policy: want 200, got %d (%s)", code, raw)
	}
	var r policyResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.PolicyHash == "" || r.PolicyHash != px.policyHashNow() {
		t.Fatalf("policy hash = %q, want the live hash %q", r.PolicyHash, px.policyHashNow())
	}
	if len(r.Rules) != 2 {
		t.Fatalf("want 2 rules, got %+v", r.Rules)
	}
	if r.Rules[0] != (policyRuleRow{Index: 0, Tool: "exec", Action: "deny", Mode: "prevent", Reason: "shell is off limits"}) {
		t.Fatalf("rule 0 = %+v", r.Rules[0])
	}
	if r.Rules[1] != (policyRuleRow{Index: 1, Tool: "write_file", Action: "hold", Mode: "detect", Reason: "writes are watched"}) {
		t.Fatalf("rule 1 = %+v", r.Rules[1])
	}
	// The listing sits behind the control-plane token.
	req := httptest.NewRequest(http.MethodGet, "/v1/policy", nil)
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no control token: want 401, got %d", rec.Code)
	}
}

func TestModeFlip(t *testing.T) {
	px, _, modesPath := policyFileProxy(t, phaseCPolicyYAML)
	px.SetApproverToken("alice", "alice-token")
	before := px.policyHashNow()

	flip := func(body, token string) (int, []byte) {
		t.Helper()
		return postAPI(t, px, "/v1/policy/mode", body, token)
	}

	// A body actor that disagrees with the approver token fails.
	code, _ := flip(`{"rule_index":0,"mode":"detect","actor":"bob"}`, "alice-token")
	if code != http.StatusForbidden {
		t.Fatalf("actor mismatch: want 403, got %d", code)
	}
	// An invalid mode fails.
	code, _ = flip(`{"rule_index":0,"mode":"wide","actor":"alice"}`, "alice-token")
	if code != http.StatusBadRequest {
		t.Fatalf("bad mode: want 400, got %d", code)
	}
	// An out-of-range index fails.
	code, _ = flip(`{"rule_index":9,"mode":"detect","actor":"alice"}`, "alice-token")
	if code != http.StatusBadRequest {
		t.Fatalf("bad index: want 400, got %d", code)
	}

	// Flip rule 0 from prevent to detect, as alice.
	code, raw := flip(`{"rule_index":0,"mode":"detect","actor":"alice"}`, "alice-token")
	if code != http.StatusOK {
		t.Fatalf("flip: want 200, got %d (%s)", code, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out["old_mode"] != "prevent" || out["new_mode"] != "detect" || out["tool"] != "exec" || out["action"] != "deny" {
		t.Fatalf("flip answer = %v", out)
	}
	after := px.policyHashNow()
	if after == before {
		t.Fatal("the effective hash must change on a flip")
	}
	if out["policy_hash"] != after {
		t.Fatalf("flip answer hash = %v, want %s", out["policy_hash"], after)
	}

	// The flip is witnessed in the ledger as a policy_change
	// event with the actor set and the full flip in the args.
	events, _ := px.Ledger().Events()
	var saw bool
	for _, e := range events {
		if e.Kind != "policy_change" {
			continue
		}
		saw = true
		if e.Actor != "alice" {
			t.Fatalf("policy_change actor = %q, want alice", e.Actor)
		}
		var args map[string]any
		if err := json.Unmarshal(e.Args, &args); err != nil {
			t.Fatal(err)
		}
		if args["rule_index"] != float64(0) || args["tool"] != "exec" || args["action"] != "deny" ||
			args["old_mode"] != "prevent" || args["new_mode"] != "detect" || args["policy_hash"] != after {
			t.Fatalf("policy_change args = %v", args)
		}
		if e.PolicyHash != after {
			t.Fatalf("policy_change event hash = %q, want %s", e.PolicyHash, after)
		}
	}
	if !saw {
		t.Fatal("no policy_change event in the ledger")
	}

	// The override file holds the flip.
	raw2, err := os.ReadFile(modesPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw2), `"rule_index":0`) || !strings.Contains(string(raw2), `"mode":"detect"`) {
		t.Fatalf("modes file = %s", raw2)
	}

	// The flipped rule now observes. An exec call runs.
	code2, res := postTool(t, px, "exec")
	if code2 != http.StatusOK || res["result"] == nil {
		t.Fatalf("exec in detect: want a forwarded call, got %d %v", code2, res)
	}
	decisions, _ := px.Ledger().EventsBySession("test-session")
	var sawDetect bool
	for _, e := range decisions {
		if e.Kind == "policy_decision" && e.Tool == "exec" && e.Mode == "detect" && e.PolicyHash == after {
			sawDetect = true
		}
	}
	if !sawDetect {
		t.Fatal("no detect policy_decision with the new hash after the flip")
	}
}

func TestModeFlipNeedsPolicyFile(t *testing.T) {
	px, _ := testProxy(t) // static deny and hold lists
	px.SetAPIToken("s3cret")
	code, raw := postAPI(t, px, "/v1/policy/mode", `{"rule_index":0,"mode":"detect","actor":"alice"}`, "s3cret")
	if code != http.StatusBadRequest {
		t.Fatalf("static policy flip: want 400, got %d (%s)", code, raw)
	}
}

func TestModeFlipPersistsAcrossRestart(t *testing.T) {
	px, policyPath, modesPath := policyFileProxy(t, phaseCPolicyYAML)
	px.SetApproverToken("alice", "alice-token")
	code, _ := postAPI(t, px, "/v1/policy/mode", `{"rule_index":1,"mode":"prevent","actor":"alice"}`, "alice-token")
	if code != http.StatusOK {
		t.Fatalf("flip: want 200, got %d", code)
	}
	flippedHash := px.policyHashNow()

	// A fresh gateway that loads the same policy file and the
	// same modes file must pick the flip back up.
	b, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	modes, err := policy.LoadModeOverrides(modesPath)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.ParseWithOverrides(b, modes)
	if err != nil {
		t.Fatal(err)
	}
	px2, err := New(upstream.URL, ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	px2.SetPolicySource(policyPath, b, modesPath, modes)
	if err := px2.LoadPolicyModes(modesPath); err != nil {
		t.Fatal(err)
	}
	rules := px2.policyNow().Rules()
	if rules[1].Mode != policy.ModePrevent {
		t.Fatalf("restarted rule 1 mode = %s, want prevent", rules[1].Mode)
	}
	if px2.policyHashNow() != flippedHash {
		t.Fatalf("restarted hash = %s, want %s", px2.policyHashNow(), flippedHash)
	}
}

func TestDashboardHeaders(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	get := func(path string) (int, http.Header, []byte) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code, rec.Header(), rec.Body.Bytes()
	}
	codeA, hA, _ := get("/approvals")
	if codeA != http.StatusOK {
		t.Fatalf("approvals page: want 200, got %d", codeA)
	}
	codeD, hD, body := get("/dashboard")
	if codeD != http.StatusOK {
		t.Fatalf("dashboard page: want 200, got %d", codeD)
	}
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "Content-Type"} {
		if hA.Get(h) != hD.Get(h) {
			t.Fatalf("header %s differs: approvals %q vs dashboard %q", h, hA.Get(h), hD.Get(h))
		}
	}
	if !strings.Contains(string(body), "Ledgerline dashboard") {
		t.Fatalf("dashboard page should name itself, got %.200s", body)
	}
	if !strings.Contains(string(body), "/v1/peers") || !strings.Contains(string(body), "/v1/sessions") || !strings.Contains(string(body), "/v1/policy") {
		t.Fatal("dashboard page should call the peers, sessions, and policy APIs")
	}
}
