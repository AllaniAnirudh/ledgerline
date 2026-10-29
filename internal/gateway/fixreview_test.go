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

// postToolSession is postTool with an explicit session and upstream
// MCP session id, for testing containment binding.
func postToolSession(t *testing.T, px *Proxy, tool, session, mcpID string) (int, map[string]any) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", session)
	if mcpID != "" {
		req.Header.Set("Mcp-Session-Id", mcpID)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// Rotating the ledger session header alone must not evade
// containment when the upstream MCP session stays the same.
func TestContainBindsMCPSession(t *testing.T) {
	px, _ := testProxyPolicy(t, policy.New(nil, nil))

	if code, _ := postToolSession(t, px, "read_file", "s1", "mcp-1"); code != 200 {
		t.Fatalf("first call should pass, got %d", code)
	}
	px.Contain("s1", "tester", "rotation test")
	if code, _ := postToolSession(t, px, "read_file", "s2", "mcp-1"); code != http.StatusForbidden {
		t.Fatalf("rotated ledger session with same MCP session should get 403, got %d", code)
	}
	if code, _ := postToolSession(t, px, "read_file", "s2", "mcp-2"); code != 200 {
		t.Fatalf("fresh MCP session should pass, got %d", code)
	}
}

// Containment must cut off a request already forwarded upstream.
// The upstream here is a stream: it writes headers and flushes
// first, as MCP streamable-HTTP responses do. That is the case
// where the upstream observes cancellation. A plain request that
// has not written headers yet may run to completion server-side
// (Go's HTTP/1.1 server does not notice the close until it
// writes), but its result is still discarded: the gateway stops
// waiting and nothing reaches the agent.
func TestContainAbortsInflight(t *testing.T) {
	entered := make(chan struct{}, 1)
	done := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		entered <- struct{}{}
		<-r.Context().Done()
		done <- struct{}{}
	}))
	t.Cleanup(upstream.Close)

	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}

	finished := make(chan struct{}, 1)
	go func() {
		postToolSession(t, px, "read_file", "s1", "mcp-1")
		close(finished)
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream handler never entered")
	}
	px.Contain("s1", "tester", "in-flight test")

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream did not observe cancellation on contain")
	}
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("forwarded request never returned after contain")
	}
}

// The forward backstop must refuse a contained session even when
// the call reaches forward without passing the ServeHTTP gate, as
// the hold release path does.
func TestForwardRefusesContainedSession(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, nil))
	px.Contain("s1", "tester", "backstop test")

	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "s1")
	rec := httptest.NewRecorder()
	px.forward(rec, req, []byte(body), nil)

	if hits.Load() != 0 {
		t.Fatalf("contained forward must never reach upstream, got %d hits", hits.Load())
	}
	if !strings.Contains(rec.Body.String(), "contained") {
		t.Fatalf("contained forward should error with contained, got %s", rec.Body.String())
	}
}

// Retries of an identical pending proposal return the existing id,
// and a full queue refuses new proposals.
func TestProposeDedupAndCap(t *testing.T) {
	p := mustPolicy(t, `version: 1
default: allow
rules:
  - tool: deploy
    action: propose
`)
	px, _ := testProxyPolicy(t, p)

	_, out1 := postTool(t, px, "deploy")
	_, out2 := postTool(t, px, "deploy")
	id1 := proposalIDFromResult(t, out1)
	id2 := proposalIDFromResult(t, out2)
	if id1 != id2 {
		t.Fatalf("identical retries should share one proposal id, got %s and %s", id1, id2)
	}
	if list := px.Proposals().List(); len(list) != 1 {
		t.Fatalf("dedup should leave one proposal, got %d", len(list))
	}

	px.Proposals().SetMaxPending(1)
	body := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"deploy","arguments":{"env":"other"}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "proposal queue full") {
		t.Fatalf("full queue should refuse, got %s", rec.Body.String())
	}
}

func proposalIDFromResult(t *testing.T, out map[string]any) string {
	t.Helper()
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", out)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", result)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	// "...proposal <id> for human application..." in both wordings.
	for _, word := range strings.Fields(text) {
		if len(word) == 32 {
			return word
		}
	}
	t.Fatalf("no proposal id in %q", text)
	return ""
}

// Expired proposals leave the queue through the control plane and
// are witnessed as expired.
func TestProposeExpiry(t *testing.T) {
	p := mustPolicy(t, `version: 1
default: allow
rules:
  - tool: deploy
    action: propose
`)
	px, _ := testProxyPolicy(t, p)
	px.Proposals().SetMaxAge(time.Millisecond)
	postTool(t, px, "deploy")
	time.Sleep(5 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/v1/proposals", nil)
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "[]") && rec.Body.String() != "[]\n" {
		t.Fatalf("expired proposal should be purged from list, got %s", rec.Body.String())
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	var sawExpired bool
	for _, e := range events {
		if e.Kind == "proposal" && e.Decision == "expired" {
			sawExpired = true
		}
	}
	if !sawExpired {
		t.Fatal("expiry not witnessed in ledger")
	}
}

// Credentials in an upstream URL must never appear in a pin error.
func TestPinRedactsCredentials(t *testing.T) {
	if got := RedactURL("http://user:s3cret@host:3001/mcp"); got != "http://host:3001/mcp" {
		t.Fatalf("redaction wrong: %q", got)
	}
	dir := t.TempDir()
	pinFile := dir + "/upstream.pin"
	if _, err := CheckUpstreamPin(pinFile, "http://user:s3cret@host:3001", false); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckUpstreamPin(pinFile, "http://user:s3cret@host:3002", false); err == nil {
		t.Fatal("changed upstream should fail")
	} else if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("pin error leaks credentials: %v", err)
	}
}
