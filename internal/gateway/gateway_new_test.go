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

func TestAPITokenGuardsControlPlane(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")

	get := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("X-Ledgerline-Token", token)
		}
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := get("/v1/approvals", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", code)
	}
	if code := get("/v1/approvals", "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("bad token: want 401, got %d", code)
	}
	if code := get("/v1/approvals", "s3cret"); code != http.StatusOK {
		t.Fatalf("good token: want 200, got %d", code)
	}
	// The approvals page itself is static and loads without a token;
	// its API calls are what get checked.
	if code := get("/approvals", ""); code != http.StatusOK {
		t.Fatalf("approvals page: want 200, got %d", code)
	}
	// The proxy path (agent traffic) is not token-guarded.
	code, _ := postTool(t, px, "read_file")
	if code != http.StatusOK {
		t.Fatalf("agent traffic should pass without token, got %d", code)
	}
}

// Regression test: a client's hop-by-hop headers (Connection: close
// from Python urllib, say) must not be forwarded upstream. Strict
// upstreams (the official MCP everything server on Express) answer
// such requests with a bare 400; this was found by dogfooding.
func TestHopByHopHeadersStripped(t *testing.T) {
	var gotConnection, gotAccept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Get("Connection")
		gotAccept = r.Header.Get("Accept")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Connection", "close")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if gotConnection != "" {
		t.Fatalf("Connection header leaked upstream: %q", gotConnection)
	}
	if gotAccept != "application/json" {
		t.Fatalf("end-to-end header lost: Accept = %q", gotAccept)
	}
}

// The decision endpoint over real HTTP: token required, approver
// token binds the recorded actor, a mismatched body actor is 403.
func TestDecisionEndpointBindsApproverActor(t *testing.T) {
	px, _ := testProxy(t)
	px.SetApproverToken("alice", "alice-token")

	done := make(chan map[string]any, 1)
	go func() {
		_, out := postTool(t, px, "write_file")
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

	decide := func(token, actor string) int {
		body := `{"decision":"approve","actor":"` + actor + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+id+"/decision", strings.NewReader(body))
		if token != "" {
			req.Header.Set("X-Ledgerline-Token", token)
		}
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := decide("", "alice"); code != http.StatusUnauthorized {
		t.Fatalf("no token: want 401, got %d", code)
	}
	if code := decide("alice-token", "mallory"); code != http.StatusForbidden {
		t.Fatalf("actor mismatch with approver token: want 403, got %d", code)
	}
	if code := decide("alice-token", "alice"); code != http.StatusOK {
		t.Fatalf("bound approver: want 200, got %d", code)
	}
	out := <-done
	if out["result"] == nil {
		t.Fatalf("approved call should forward, got %v", out)
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	var actor string
	for _, e := range events {
		if e.Kind == "approval" && e.Decision == "approve" {
			actor = e.Actor
		}
	}
	if actor != "alice" {
		t.Fatalf("ledger approval actor = %q, want alice (bound to token)", actor)
	}
}

func TestBearerTokenAccepted(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/v1/verify", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bearer token: want 200, got %d", rec.Code)
	}
}

func TestBatchBodyRejectedAndWitnessed(t *testing.T) {
	px, _ := testProxy(t)
	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec","arguments":{}}}]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "batch-session")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "batch") {
		t.Fatalf("batch body should be refused, got %s", rec.Body.String())
	}
	events, _ := px.Ledger().EventsBySession("batch-session")
	if len(events) != 1 || events[0].Kind != "policy_decision" || events[0].Decision != "deny" {
		t.Fatalf("batch refusal should be witnessed as one deny event, got %v", events)
	}
}

func TestConnectionNamedHeadersStripped(t *testing.T) {
	var gotDebug string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDebug = r.Header.Get("X-Debug")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()
	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Connection", "X-Debug")
	req.Header.Set("X-Debug", "1")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if gotDebug != "" {
		t.Fatalf("Connection-named header leaked upstream: %q", gotDebug)
	}
}

func TestYAMLPolicyArgsMatchThroughGateway(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	defer upstream.Close()

	p, err := policy.Parse([]byte(`
version: 1
default: allow
rules:
  - tool: write_file
    action: hold
    args_match:
      path: "/etc/*"
`))
	if err != nil {
		t.Fatal(err)
	}
	px, err := New(upstream.URL, ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)

	post := func(args string) map[string]any {
		body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":` + args + `}}`
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("X-Ledgerline-Session", "yaml-session")
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}

	// /tmp write: no rule matches, default allow, straight through.
	if out := post(`{"path":"/tmp/x"}`); out["result"] == nil {
		t.Fatalf("tmp write should pass, got %v", out)
	}

	// /etc write: held, then a deny decision blocks it.
	done := make(chan map[string]any, 1)
	go func() { done <- post(`{"path":"/etc/hosts"}`) }()
	var id string
	for i := 0; i < 50 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
		}
	}
	if id == "" {
		t.Fatal("etc write was not held")
	}
	px.Approvals().Decide(id, false, "tester")
	out := <-done
	if out["error"] == nil {
		t.Fatalf("denied etc write should error, got %v", out)
	}
}
