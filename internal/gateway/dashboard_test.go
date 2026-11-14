package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
	"github.com/AllaniAnirudh/ledgerline/internal/token"
)

var dashboardKey = []byte("0123456789abcdef0123456789abcdef")

func mintAgent(t *testing.T, agentID string, ttl time.Duration) string {
	t.Helper()
	tok, _, err := token.Issue(dashboardKey, agentID, "buppy", ttl)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// authProxy builds a proxy with agent tokens required. The
// revocation file lives in a temp dir. The control-plane token
// is "s3cret".
func authProxy(t *testing.T, p *policy.Policy) (*Proxy, string) {
	t.Helper()
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
	revokeFile := filepath.Join(t.TempDir(), "revoked.json")
	if err := px.SetTokenKey(dashboardKey, revokeFile); err != nil {
		t.Fatal(err)
	}
	px.SetRequireAgentToken(true)
	px.SetAPIToken("s3cret")
	return px, revokeFile
}

func postToolAuth(t *testing.T, px *Proxy, tool, session, tok string) (int, map[string]any) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", session)
	if tok != "" {
		req.Header.Set(agentTokenHeader, tok)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func getAPI(t *testing.T, px *Proxy, path string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Ledgerline-Token", "s3cret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func TestProxyRequiresAgentToken(t *testing.T) {
	px, _ := authProxy(t, policy.New([]string{"exec"}, []string{"write_file"}))

	// No token: 401, and nothing is witnessed.
	code, out := postToolAuth(t, px, "read_file", "s1", "")
	if code != http.StatusUnauthorized {
		t.Fatalf("tokenless: want 401, got %d (%v)", code, out)
	}
	events, _ := px.Ledger().Events()
	if len(events) != 0 {
		t.Fatalf("tokenless rejection should witness nothing, got %d events", len(events))
	}

	// Expired token: 401, and nothing is witnessed.
	expired := mintAgent(t, "agent-1", time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	code, _ = postToolAuth(t, px, "read_file", "s1", expired)
	if code != http.StatusUnauthorized {
		t.Fatalf("expired: want 401, got %d", code)
	}
	events, _ = px.Ledger().Events()
	if len(events) != 0 {
		t.Fatalf("expired rejection should witness nothing, got %d events", len(events))
	}

	// Wrong-key token: 401.
	other, _, err := token.Issue([]byte("fedcba9876543210fedcba9876543210"), "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = postToolAuth(t, px, "read_file", "s1", other)
	if code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", code)
	}

	// Valid token: the call forwards, and the agent id lands
	// on the tool_call and policy_decision events.
	code, out = postToolAuth(t, px, "read_file", "s1", mintAgent(t, "agent-1", time.Hour))
	if code != http.StatusOK || out["result"] == nil {
		t.Fatalf("valid token: want a forwarded call, got %d %v", code, out)
	}
	events, _ = px.Ledger().EventsBySession("s1")
	if len(events) != 2 {
		t.Fatalf("want 2 events, got %d", len(events))
	}
	for _, e := range events {
		if e.AgentID != "agent-1" {
			t.Fatalf("event %s has agent id %q, want agent-1", e.Kind, e.AgentID)
		}
	}
}

func TestRevokedTokenRejectedAndPersisted(t *testing.T) {
	px, revokeFile := authProxy(t, policy.New(nil, nil))
	tok := mintAgent(t, "agent-1", time.Hour)
	claims, err := token.Validate(dashboardKey, tok)
	if err != nil {
		t.Fatal(err)
	}

	// Revoke through the control plane.
	body := `{"jti":"` + claims.ID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/tokens/revoke", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Token", "s3cret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	// The revocation is witnessed, with the jti in the args.
	events, _ := px.Ledger().Events()
	var sawRevoke bool
	for _, e := range events {
		if e.Kind == "token_revoked" && strings.Contains(string(e.Args), claims.ID) {
			sawRevoke = true
		}
	}
	if !sawRevoke {
		t.Fatal("revoke should witness a token_revoked event with the jti")
	}
	// The file holds the jti.
	raw, err := os.ReadFile(revokeFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), claims.ID) {
		t.Fatalf("revocation file should hold the jti, got %s", raw)
	}
	// The token is rejected from then on.
	code, _ := postToolAuth(t, px, "read_file", "s1", tok)
	if code != http.StatusUnauthorized {
		t.Fatalf("revoked: want 401, got %d", code)
	}

	// A fresh proxy that loads the same file rejects it too.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()
	px2, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := px2.SetTokenKey(dashboardKey, revokeFile); err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{}`))
	req2.Header.Set(agentTokenHeader, tok)
	if _, err := px2.validateAgentToken(req2); err == nil {
		t.Fatal("a restarted gateway should still reject a revoked token")
	}
}

func TestRevokeNeedsJTI(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	req := httptest.NewRequest(http.MethodPost, "/v1/tokens/revoke", strings.NewReader(`{}`))
	req.Header.Set("X-Ledgerline-Token", "s3cret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty jti: want 400, got %d", rec.Code)
	}
}

func TestAgentHeadersNeverReachUpstream(t *testing.T) {
	var gotAgent, gotAuth, gotControl string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = r.Header.Get(agentTokenHeader)
		gotAuth = r.Header.Get("Authorization")
		gotControl = r.Header.Get("X-Ledgerline-Token")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()
	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := px.SetTokenKey(dashboardKey, filepath.Join(t.TempDir(), "revoked.json")); err != nil {
		t.Fatal(err)
	}
	px.SetRequireAgentToken(true)

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "s1")
	req.Header.Set(agentTokenHeader, mintAgent(t, "agent-1", time.Hour))
	req.Header.Set("Authorization", "Bearer client-secret")
	req.Header.Set("X-Ledgerline-Token", "control-secret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if gotAgent != "" {
		t.Fatalf("agent token leaked upstream: %q", gotAgent)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization leaked upstream: %q", gotAuth)
	}
	if gotControl != "" {
		t.Fatalf("control token leaked upstream: %q", gotControl)
	}
}

func TestHoldKeepsAgentID(t *testing.T) {
	px, _ := authProxy(t, policy.New([]string{"exec"}, []string{"write_file"}))
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postToolAuth(t, px, "write_file", "s1", mintAgent(t, "agent-1", time.Hour))
		done <- out
	}()
	var id string
	for i := 0; i < 50 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
			if list[0].AgentID != "agent-1" {
				t.Fatalf("held call agent id = %q, want agent-1", list[0].AgentID)
			}
		}
	}
	if id == "" {
		t.Fatal("held call never appeared")
	}
	if !px.Approvals().Decide(id, true, "tester") {
		t.Fatal("decide failed")
	}
	out := <-done
	if out["result"] == nil {
		t.Fatalf("approved call should forward, got %v", out)
	}
	events, _ := px.Ledger().EventsBySession("s1")
	for _, e := range events {
		if e.Kind == "approval" || e.Kind == "tool_call" {
			if e.AgentID != "agent-1" {
				t.Fatalf("event %s/%s has agent id %q, want agent-1", e.Kind, e.Decision, e.AgentID)
			}
		}
	}
}

func TestEventsFiltersAndPaging(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	postTool(t, px, "read_file") // test-session: allow
	postTool(t, px, "exec")      // test-session: deny
	// A second session, via a direct call with another header.
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "other-session")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("other session call: want 200, got %d", rec.Code)
	}

	type resp struct {
		Events []ledger.Event `json:"events"`
		Total  int            `json:"total"`
		Limit  int            `json:"limit"`
		Offset int            `json:"offset"`
	}
	get := func(path string) resp {
		t.Helper()
		code, raw := getAPI(t, px, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s: want 200, got %d (%s)", path, code, raw)
		}
		var r resp
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	// Whole chain: 2 + 1 + 2 = 5 events.
	if r := get("/v1/events"); r.Total != 5 || len(r.Events) != 5 {
		t.Fatalf("all events: want total 5, got %+v", r)
	}
	if r := get("/v1/events?session=test-session"); r.Total != 3 {
		t.Fatalf("session filter: want total 3, got %d", r.Total)
	}
	if r := get("/v1/events?kind=tool_call"); r.Total != 2 {
		t.Fatalf("kind filter: want total 2, got %d", r.Total)
	}
	if r := get("/v1/events?decision=deny"); r.Total != 1 {
		t.Fatalf("decision filter: want total 1, got %d", r.Total)
	}
	if r := get("/v1/events?tool=exec"); r.Total != 1 {
		t.Fatalf("tool filter: want total 1, got %d", r.Total)
	}
	if r := get("/v1/events?mode=prevent&decision=deny"); r.Total != 1 {
		t.Fatalf("mode filter: want total 1, got %d", r.Total)
	}
	// Paging: page 2 of the session, one row.
	if r := get("/v1/events?session=test-session&limit=1&offset=1"); r.Total != 3 || len(r.Events) != 1 || r.Offset != 1 {
		t.Fatalf("paging: want total 3 with 1 row at offset 1, got %+v", r)
	}
	// Limit clamps to 500.
	if r := get("/v1/events?limit=999"); r.Limit != 500 {
		t.Fatalf("limit should clamp to 500, got %d", r.Limit)
	}
	// Time range in the future matches nothing.
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if r := get("/v1/events?from=" + future); r.Total != 0 {
		t.Fatalf("future from: want total 0, got %d", r.Total)
	}
	// Bad time is 400.
	code, _ := getAPI(t, px, "/v1/events?from=not-a-time")
	if code != http.StatusBadRequest {
		t.Fatalf("bad from: want 400, got %d", code)
	}
	// The endpoint sits behind the control-plane token.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec2 := httptest.NewRecorder()
	px.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("no control token: want 401, got %d", rec2.Code)
	}
}

func TestSessionsSummary(t *testing.T) {
	p, err := policy.Parse([]byte(`
version: 1
default: allow
rules:
  - tool: exec
    action: deny
  - tool: rm
    action: deny
    mode: detect
  - tool: write_file
    action: hold
  - tool: deploy
    action: propose
`))
	if err != nil {
		t.Fatal(err)
	}
	px, _ := authProxy(t, p)
	tok1 := mintAgent(t, "agent-1", time.Hour)
	tok2 := mintAgent(t, "agent-2", time.Hour)

	if code, _ := postToolAuth(t, px, "read_file", "s1", tok1); code != 200 {
		t.Fatalf("read: want 200, got %d", code)
	}
	if code, _ := postToolAuth(t, px, "exec", "s1", tok1); code != 200 {
		t.Fatalf("exec: want 200 with a JSON-RPC error, got %d", code)
	}
	if code, _ := postToolAuth(t, px, "rm", "s1", tok1); code != 200 {
		t.Fatalf("rm in detect: want 200, got %d", code)
	}
	if code, _ := postToolAuth(t, px, "deploy", "s1", tok1); code != 200 {
		t.Fatalf("deploy: want 200, got %d", code)
	}
	// Held call on s2, approved by a human.
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postToolAuth(t, px, "write_file", "s2", tok2)
		done <- out
	}()
	var id string
	for i := 0; i < 50 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
		}
	}
	if id == "" {
		t.Fatal("held call never appeared")
	}
	px.Approvals().Decide(id, true, "tester")
	if out := <-done; out["result"] == nil {
		t.Fatalf("approved call should forward, got %v", out)
	}
	// Contain s1.
	px.Contain("s1", "tester", "test", "")

	code, raw := getAPI(t, px, "/v1/sessions")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sessions: want 200, got %d (%s)", code, raw)
	}
	var rows []sessionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	byID := map[string]sessionRow{}
	for _, row := range rows {
		byID[row.SessionID] = row
	}
	s1, ok := byID["s1"]
	if !ok {
		t.Fatalf("no s1 row in %v", rows)
	}
	if s1.TotalCalls != 2 || s1.Allowed != 2 {
		t.Fatalf("s1 calls: want total 2 allowed 2, got %+v", s1)
	}
	if s1.Denied != 1 {
		t.Fatalf("s1 denied: want 1, got %d", s1.Denied)
	}
	if s1.Detected != 1 {
		t.Fatalf("s1 detected: want 1, got %d", s1.Detected)
	}
	if s1.Proposals != 1 {
		t.Fatalf("s1 proposals: want 1, got %d", s1.Proposals)
	}
	if s1.Contained != 1 || s1.Status != "contained" {
		t.Fatalf("s1 containment: want count 1 status contained, got %+v", s1)
	}
	if len(s1.AgentIDs) != 1 || s1.AgentIDs[0] != "agent-1" {
		t.Fatalf("s1 agent ids: want [agent-1], got %v", s1.AgentIDs)
	}
	if s1.FirstSeen == "" || s1.LastSeen == "" {
		t.Fatal("s1 needs first and last seen")
	}
	s2, ok := byID["s2"]
	if !ok {
		t.Fatalf("no s2 row in %v", rows)
	}
	if s2.TotalCalls != 1 || s2.Allowed != 1 || s2.Holds != 1 {
		t.Fatalf("s2: want total 1 allowed 1 holds 1, got %+v", s2)
	}
	if s2.Status != "active" {
		t.Fatalf("s2 status: want active, got %q", s2.Status)
	}
	if len(s2.AgentIDs) != 1 || s2.AgentIDs[0] != "agent-2" {
		t.Fatalf("s2 agent ids: want [agent-2], got %v", s2.AgentIDs)
	}
}

// TestSessionsSkipsSystemSessions checks that system events
// never appear as roster rows. The tools baseline writes with
// an empty session. Token revokes and policy changes write
// under "gateway". Neither is an agent session.
func TestSessionsSkipsSystemSessions(t *testing.T) {
	p, err := policy.Parse([]byte(`
version: 1
default: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	px, _ := authProxy(t, p)
	tok := mintAgent(t, "agent-1", time.Hour)
	if _, err := px.Ledger().Append("", "tools_baseline", "", nil, "establish", "gateway"); err != nil {
		t.Fatal(err)
	}
	if _, err := px.Ledger().Append("gateway", "token_revoked", "(token)", nil, "revoke", "alice"); err != nil {
		t.Fatal(err)
	}
	if code, _ := postToolAuth(t, px, "read_file", "s1", tok); code != 200 {
		t.Fatalf("read: want 200, got %d", code)
	}
	code, raw := getAPI(t, px, "/v1/sessions")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sessions: want 200, got %d (%s)", code, raw)
	}
	var rows []sessionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SessionID != "s1" {
		t.Fatalf("sessions: want only s1, got %v", rows)
	}
}
