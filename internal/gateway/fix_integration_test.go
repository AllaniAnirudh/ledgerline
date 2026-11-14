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
	"github.com/AllaniAnirudh/ledgerline/internal/token"
)

// TestHeldDriftDeniedHasNoAllow proves the held path witnesses
// no allow for a call that never ran. A held call is approved,
// then the drift gate denies it at forward time because the
// tool surface moved. The ledger must hold the approve and the
// drift denial, and no tool_call allow. Before the witness
// move, release recorded the allow before forward ran.
func TestHeldDriftDeniedHasNoAllow(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "x"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, []string{"x"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(10 * time.Second)
	postList(t, px)
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postToolHeaders(t, px, "x", `{}`, nil)
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		done <- m
	}()
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
		}
	}
	if id == "" {
		t.Fatal("held call never appeared")
	}
	// The surface moves without x. A human accepts it, so the
	// baseline drops x. Approving the stale hold must not
	// forward x, and must not witness an allow for it.
	stub.set([]listTool{{Name: "y"}})
	px.SetToolsReapprovePending("tester")
	postList(t, px)
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+id+"/decision", strings.NewReader(`{"decision":"approve","actor":"tester"}`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decision should succeed, got %d", rec.Code)
	}
	out := <-done
	errObj, _ := out["error"].(map[string]any)
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "not in baseline") {
		t.Fatalf("stale hold approved after re-baseline should be drift-denied, got %v", out)
	}
	if stub.hits.Load() != 0 {
		t.Fatalf("drift-denied release must not reach upstream, hits=%d", stub.hits.Load())
	}
	if n := countEvents(t, px, "approval", "approve"); n != 1 {
		t.Fatalf("approve should be witnessed once, got %d", n)
	}
	if n := countEvents(t, px, "tools_drift", "deny"); n != 1 {
		t.Fatalf("drift denial should be witnessed once, got %d", n)
	}
	if n := countEvents(t, px, "tool_call", "allow"); n != 0 {
		t.Fatalf("no tool_call allow may exist for a call that never ran, got %d", n)
	}
}

// TestControlBodyTooLarge proves a control-plane POST with a
// body over the 1 MiB cap is refused instead of buffered.
func TestControlBodyTooLarge(t *testing.T) {
	px, _ := testProxy(t)
	big := strings.Repeat("a", 2<<20)
	body := `{"rule_index":0,"mode":"detect","actor":"` + big + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/policy/mode", strings.NewReader(body))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized control body: want 400, got %d", rec.Code)
	}
}

// TestTokenStrictAudienceRejectsLegacy proves strict audience
// mode refuses a legacy token with no audience, while an
// audience-bound token for this gateway still passes.
func TestTokenStrictAudienceRejectsLegacy(t *testing.T) {
	px, _ := testProxy(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := px.SetTokenKey(key, ""); err != nil {
		t.Fatal(err)
	}
	px.SetRequireAgentToken(true)
	px.SetTokenAudience("gw-a")
	px.SetStrictTokenAudience(true)
	legacy, _, err := token.Issue(key, "agent-1", "owner", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := postToolHeaders(t, px, "echo", `{}`, map[string]string{"X-Ledgerline-Agent-Token": legacy})
	if code != http.StatusUnauthorized {
		t.Fatalf("legacy token in strict mode: want 401, got %d", code)
	}
	bound, _, err := token.IssueWithAudience(key, "agent-1", "owner", time.Hour, "gw-a")
	if err != nil {
		t.Fatal(err)
	}
	code, _ = postToolHeaders(t, px, "echo", `{}`, map[string]string{"X-Ledgerline-Agent-Token": bound})
	if code != http.StatusOK {
		t.Fatalf("audience-bound token in strict mode: want 200, got %d", code)
	}
}
