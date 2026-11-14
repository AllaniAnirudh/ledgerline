package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// Tests for the proxy, hook, roster, and dashboard fixes.
// M3: drift in detect mode is observed and runs. The fresh path
// never records an allow for a call that never ran.
// M4: hook traffic carries an agent id.
// M5: the session name "gateway" is reserved. The roster filters
// system rows by kind, not by session name.
// L12: drift denials count under denied.
// L14: the dashboard polls every 60 seconds, only while visible.

func driftProxy(t *testing.T, yaml string, tools []listTool) (*Proxy, *mutableToolsStub) {
	t.Helper()
	p, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	stub := &mutableToolsStub{tools: tools}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)
	postList(t, px)
	if !px.HasToolsBaseline() {
		t.Fatal("tools/list should establish a baseline")
	}
	return px, stub
}

func postHookAgent(t *testing.T, px *Proxy, tool, args, session, apiToken, agentToken string) (int, map[string]any) {
	t.Helper()
	body := `{"tool":"` + tool + `","arguments":` + args + `,"session":"` + session + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/hook", strings.NewReader(body))
	if apiToken != "" {
		req.Header.Set("X-Ledgerline-Token", apiToken)
	}
	if agentToken != "" {
		req.Header.Set(agentTokenHeader, agentToken)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func sessionEvents(t *testing.T, px *Proxy, session string) []ledger.Event {
	t.Helper()
	events, err := px.Ledger().EventsBySession(session)
	if err != nil {
		t.Fatal(err)
	}
	return events
}

func TestFixDriftDetectForwards(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: deny\n    mode: detect\n", []listTool{{Name: "read"}})
	before := stub.hits.Load()
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("drifted tool in detect mode should run, got %s", out)
	}
	if stub.hits.Load() != before+1 {
		t.Fatalf("drifted tool in detect mode should reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 2 {
		t.Fatalf("want policy_decision plus tool_call, got %d: %+v", len(events), events)
	}
	pd, tc := events[0], events[1]
	if pd.Kind != "policy_decision" || pd.Tool != "evil" || pd.Decision != "deny" || pd.Mode != "detect" {
		t.Fatalf("policy_decision = %+v, want deny/detect for evil", pd)
	}
	if tc.Kind != "tool_call" || tc.Tool != "evil" || tc.Decision != "allow" || tc.Mode != "detect" {
		t.Fatalf("tool_call = %+v, want allow/detect for evil", tc)
	}
	if tc.DecisionID == "" || tc.DecisionID != pd.DecisionID {
		t.Fatalf("tool_call id %q does not match policy_decision id %q", tc.DecisionID, pd.DecisionID)
	}
	for _, e := range events {
		if e.Kind == "tools_drift" {
			t.Fatalf("detect-mode drift must not record a tools_drift denial: %+v", e)
		}
	}
}

func TestFixDriftPreventDeniesWithoutAllow(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: deny\n", []listTool{{Name: "read"}})
	before := stub.hits.Load()
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("drifted tool in prevent mode should be denied as drift, got %s", out)
	}
	if stub.hits.Load() != before {
		t.Fatalf("drift-denied call must not reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 1 {
		t.Fatalf("want one tools_drift denial, got %d: %+v", len(events), events)
	}
	if events[0].Kind != "tools_drift" || events[0].Decision != "deny" {
		t.Fatalf("event = %+v, want tools_drift deny", events[0])
	}
}

func TestFixForwardDriftDetectForwards(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\ndefault: allow\n", []listTool{{Name: "read"}})
	// The surface moves after arrival. A human accepts it.
	// "read" is now outside the new baseline.
	px.SetToolsReapprovePending("tester")
	if err := px.applyToolsList(ledger.ToolsBaseline{Tools: []ledger.BaselineTool{{Name: "other"}}}, "gateway"); err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	req = withToolCallWitness(req, toolCallWitness{tool: "read", args: json.RawMessage(`{}`), decisionID: "0123456789abcdef0123456789abcdef", mode: "detect", detect: true})
	rec := httptest.NewRecorder()
	before := stub.hits.Load()
	px.forward(rec, req, []byte(body), nil)
	if strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("forward-time drift in detect mode should run, got %s", rec.Body.String())
	}
	if stub.hits.Load() != before+1 {
		t.Fatalf("forward-time drift in detect mode should reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	var sawDrift, sawAllow bool
	for _, e := range events {
		if e.Kind == "tools_drift" && e.Decision == "deny" && e.Mode == "detect" {
			sawDrift = true
		}
		if e.Kind == "tool_call" && e.Decision == "allow" {
			sawAllow = true
		}
	}
	if !sawDrift {
		t.Fatalf("want a tools_drift deny with mode detect, got %+v", events)
	}
	if !sawAllow {
		t.Fatalf("want a tool_call allow for the call that ran, got %+v", events)
	}
}

func TestFixForwardDriftPreventDeniesWithoutAllow(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\ndefault: allow\n", []listTool{{Name: "read"}})
	px.SetToolsReapprovePending("tester")
	if err := px.applyToolsList(ledger.ToolsBaseline{Tools: []ledger.BaselineTool{{Name: "other"}}}, "gateway"); err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	req = withToolCallWitness(req, toolCallWitness{tool: "read", args: json.RawMessage(`{}`), decisionID: "0123456789abcdef0123456789abcdef", mode: "prevent", detect: false})
	rec := httptest.NewRecorder()
	before := stub.hits.Load()
	px.forward(rec, req, []byte(body), nil)
	if !strings.Contains(rec.Body.String(), "not in baseline") {
		t.Fatalf("forward-time drift in prevent mode should be denied as drift, got %s", rec.Body.String())
	}
	if stub.hits.Load() != before {
		t.Fatalf("drift-denied forward must not reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 1 {
		t.Fatalf("want one tools_drift denial and no allow, got %d: %+v", len(events), events)
	}
	if events[0].Kind != "tools_drift" || events[0].Decision != "deny" {
		t.Fatalf("event = %+v, want tools_drift deny", events[0])
	}
}

func TestFixHookAgentTokenAttributed(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	tok := mintAgent(t, "agent-9", time.Hour)
	code, out := postHookAgent(t, px, "bash", `{"command":"ls"}`, "s1", "s3cret", tok)
	if code != http.StatusOK || out["decision"] != "allow" {
		t.Fatalf("hook with agent token: want 200/allow, got %d %v", code, out)
	}
	events := sessionEvents(t, px, "s1")
	if len(events) != 2 {
		t.Fatalf("want policy_decision plus tool_call, got %d: %+v", len(events), events)
	}
	for _, e := range events {
		if e.AgentID != "agent-9" {
			t.Fatalf("event %+v should carry agent id agent-9", e)
		}
	}
}

func TestFixHookAgentTokenMissingDenied(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	code, _ := postHookAgent(t, px, "bash", `{"command":"ls"}`, "s1", "s3cret", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("hook without agent token when required: want 401, got %d", code)
	}
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("rejected hook must witness nothing, got %+v", events)
	}
}

func TestFixHookAgentTokenInvalidDenied(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	code, _ := postHookAgent(t, px, "bash", `{"command":"ls"}`, "s1", "s3cret", "bogus")
	if code != http.StatusUnauthorized {
		t.Fatalf("hook with bad agent token: want 401, got %d", code)
	}
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("rejected hook must witness nothing, got %+v", events)
	}
}

func TestFixHookNoTokenUnattributed(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	code, out := postHookAgent(t, px, "bash", `{"command":"ls"}`, "s1", "", "")
	if code != http.StatusOK || out["decision"] != "allow" {
		t.Fatalf("hook without agent token when not required: want 200/allow, got %d %v", code, out)
	}
	for _, e := range sessionEvents(t, px, "s1") {
		if e.AgentID != "" {
			t.Fatalf("event %+v should stay unattributed without a token", e)
		}
	}
}

func TestFixHookHoldAgentAttributed(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, []string{"bash"}))
	tok := mintAgent(t, "agent-9", time.Hour)
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postHookAgent(t, px, "bash", `{"command":"ls"}`, "s1", "s3cret", tok)
		done <- out
	}()
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
		}
	}
	if id == "" {
		t.Fatal("held hook call never appeared")
	}
	if !px.Approvals().Decide(id, true, "tester") {
		t.Fatal("decision should succeed")
	}
	out := <-done
	if out["decision"] != "allow" {
		t.Fatalf("approved hold should allow, got %v", out)
	}
	events := sessionEvents(t, px, "s1")
	var sawApprove, sawAllow bool
	for _, e := range events {
		if e.Kind == "approval" && e.Decision == "approve" && e.AgentID == "agent-9" {
			sawApprove = true
		}
		if e.Kind == "tool_call" && e.Decision == "allow" && e.AgentID == "agent-9" {
			sawAllow = true
		}
	}
	if !sawApprove || !sawAllow {
		t.Fatalf("want attributed approval and tool_call, got %+v", events)
	}
}

func TestFixSessionGatewayRejected(t *testing.T) {
	px, _ := testProxy(t)
	for _, name := range []string{"gateway", "GATEWAY"} {
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("X-Ledgerline-Session", name)
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("session %q: want 400, got %d", name, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "reserved") {
			t.Fatalf("session %q: want a reserved-name error, got %s", name, rec.Body.String())
		}
	}
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("rejected session must witness nothing, got %+v", events)
	}
}

func TestFixHookSessionGatewayRejected(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := postHook(t, px, "bash", `{}`, "gateway", "")
	if code != http.StatusBadRequest {
		t.Fatalf("hook session gateway: want 400, got %d", code)
	}
}

func TestFixSessionsRosterShowsGatewaySession(t *testing.T) {
	px, _ := testProxy(t)
	if _, err := px.Ledger().Append("", "tools_baseline", "", nil, "establish", "gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := px.Ledger().Append("gateway", "token_revoked", "(token)", nil, "revoke", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := px.Ledger().Append("gateway", "policy_change", "exec", nil, "policy_change", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := px.Ledger().Append("gateway", "tool_call", "read", nil, "allow", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := px.Ledger().Append("s1", "tool_call", "read", nil, "allow", ""); err != nil {
		t.Fatal(err)
	}
	code, raw := getAPI(t, px, "/v1/sessions")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sessions: want 200, got %d (%s)", code, raw)
	}
	var rows []sessionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("roster should show s1 and the legacy gateway session, got %v", rows)
	}
	if rows[0].SessionID != "gateway" || rows[1].SessionID != "s1" {
		t.Fatalf("roster rows = %v, want gateway then s1", rows)
	}
}

func TestFixSessionsDriftDeniedCounted(t *testing.T) {
	px, _ := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: deny\n", []listTool{{Name: "read"}})
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("drifted tool should be denied as drift, got %s", out)
	}
	code, raw := getAPI(t, px, "/v1/sessions")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sessions: want 200, got %d (%s)", code, raw)
	}
	var rows []sessionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SessionID != "test-session" {
		t.Fatalf("roster = %v, want one test-session row", rows)
	}
	if rows[0].Denied != 1 {
		t.Fatalf("denied_calls = %d, want 1 for the drift denial", rows[0].Denied)
	}
	if rows[0].TotalCalls != 0 || rows[0].Allowed != 0 {
		t.Fatalf("row = %+v, want zero calls and zero allowed", rows[0])
	}
}

func TestFixDashboardPollInterval(t *testing.T) {
	html := string(DashboardHTML())
	if !strings.Contains(html, "60000") {
		t.Fatal("dashboard should poll every 60 seconds")
	}
	if !strings.Contains(html, "visibilitychange") || !strings.Contains(html, "document.hidden") {
		t.Fatal("dashboard should poll only while the page is visible")
	}
	if strings.Contains(html, "10000") {
		t.Fatal("dashboard should not poll every 10 seconds")
	}
	if !strings.Contains(html, "Drift is a boundary gate") {
		t.Fatal("dashboard drift view should label drift as a boundary gate")
	}
}
