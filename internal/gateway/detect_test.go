package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

const detectPolicyYAML = `
version: 1
rules:
  - tool: exec
    action: deny
    mode: detect
  - tool: write_file
    action: hold
    mode: detect
  - tool: "drop_*"
    action: contain
    mode: detect
  - tool: deploy
    action: propose
    mode: detect
`

const preventPolicyYAML = `
version: 1
rules:
  - tool: exec
    action: deny
  - tool: write_file
    action: hold
  - tool: "drop_*"
    action: contain
  - tool: deploy
    action: propose
`

func testProxyWithPolicy(t *testing.T, yaml string) (*Proxy, *policy.Policy) {
	t.Helper()
	p, err := policy.Parse([]byte(yaml))
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
	return px, p
}

// decisionPair returns the policy_decision event and the tool_call
// event for one tool, in order. It fails the test when the pair
// is not exactly what detect mode must record.
func decisionPair(t *testing.T, px *Proxy, tool, wantDecision string) (ledger.Event, ledger.Event) {
	t.Helper()
	events, err := px.Ledger().EventsBySession("test-session")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 ledger events for %s, got %d: %+v", tool, len(events), events)
	}
	pd, tc := events[0], events[1]
	if pd.Kind != "policy_decision" || pd.Tool != tool || pd.Decision != wantDecision || pd.Mode != "detect" {
		t.Fatalf("policy_decision = %+v, want kind policy_decision tool %s decision %s mode detect", pd, tool, wantDecision)
	}
	if pd.DecisionID == "" || len(pd.DecisionID) != 32 {
		t.Fatalf("policy_decision id = %q, want 32 hex chars", pd.DecisionID)
	}
	if pd.PolicyHash == "" {
		t.Fatal("policy_decision has no policy hash")
	}
	if tc.Kind != "tool_call" || tc.Tool != tool || tc.Decision != "allow" || tc.Mode != "detect" {
		t.Fatalf("tool_call = %+v, want kind tool_call tool %s decision allow mode detect", tc, tool)
	}
	if tc.DecisionID != pd.DecisionID {
		t.Fatalf("tool_call id %q does not match policy_decision id %q", tc.DecisionID, pd.DecisionID)
	}
	return pd, tc
}

func TestProxyDetectDenyForwards(t *testing.T) {
	px, p := testProxyWithPolicy(t, detectPolicyYAML)
	code, out := postTool(t, px, "exec")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("detected deny should forward, got error: %v", out["error"])
	}
	if out["result"] == nil {
		t.Fatalf("detected deny should return the upstream result, got %v", out)
	}
	pd, _ := decisionPair(t, px, "exec", "deny")
	if pd.PolicyHash != p.Hash() {
		t.Fatalf("policy hash = %q, want %q", pd.PolicyHash, p.Hash())
	}
}

func TestProxyDetectHoldForwardsWithoutQueue(t *testing.T) {
	px, _ := testProxyWithPolicy(t, detectPolicyYAML)
	code, out := postTool(t, px, "write_file")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("detected hold should forward, got error: %v", out["error"])
	}
	if len(px.Approvals().List()) != 0 {
		t.Fatal("detected hold queued an approval")
	}
	decisionPair(t, px, "write_file", "hold")
}

func TestProxyDetectContainForwardsWithoutFreeze(t *testing.T) {
	px, _ := testProxyWithPolicy(t, detectPolicyYAML)
	code, out := postTool(t, px, "drop_table")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("detected contain should forward, got error: %v", out["error"])
	}
	if px.IsContained("test-session", "") {
		t.Fatal("detected contain froze the session")
	}
	decisionPair(t, px, "drop_table", "contain")
	// The session still works after a detected contain.
	code, out = postTool(t, px, "read_file")
	if code != 200 || out["error"] != nil {
		t.Fatalf("call after detected contain should forward, got %d %v", code, out)
	}
}

func TestProxyDetectProposeForwardsWithoutQueue(t *testing.T) {
	px, _ := testProxyWithPolicy(t, detectPolicyYAML)
	code, out := postTool(t, px, "deploy")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("detected propose should forward, got error: %v", out["error"])
	}
	if out["result"] == nil {
		t.Fatalf("detected propose should return the upstream result, got %v", out)
	}
	if len(px.Proposals().List()) != 0 {
		t.Fatal("detected propose entered the proposal queue")
	}
	events, err := px.Ledger().EventsBySession("test-session")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("want 3 ledger events for detected propose, got %d: %+v", len(events), events)
	}
	pd, pr, tc := events[0], events[1], events[2]
	if pd.Kind != "policy_decision" || pd.Decision != "propose" || pd.Mode != "detect" {
		t.Fatalf("policy_decision = %+v, want propose/detect", pd)
	}
	if pr.Kind != "proposal" || pr.Decision != "propose" || pr.Mode != "detect" {
		t.Fatalf("proposal = %+v, want kind proposal decision propose mode detect", pr)
	}
	if pr.DecisionID != pd.DecisionID {
		t.Fatalf("proposal id %q does not match policy_decision id %q", pr.DecisionID, pd.DecisionID)
	}
	if tc.Kind != "tool_call" || tc.Decision != "allow" || tc.Mode != "detect" || tc.DecisionID != pd.DecisionID {
		t.Fatalf("tool_call = %+v, want allow/detect with the same id", tc)
	}
}

func TestProxyPreventStillBlocks(t *testing.T) {
	px, _ := testProxyWithPolicy(t, preventPolicyYAML)
	// Deny still blocks.
	_, out := postTool(t, px, "exec")
	if errObj, ok := out["error"].(map[string]any); !ok || !strings.Contains(errObj["message"].(string), "denied") {
		t.Fatalf("prevent deny should block, got %v", out)
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	if len(events) != 1 || events[0].Kind != "policy_decision" || events[0].Decision != "deny" || events[0].Mode != "prevent" {
		t.Fatalf("prevent deny events = %+v, want one policy_decision deny/prevent", events)
	}
	if events[0].DecisionID == "" || events[0].PolicyHash == "" {
		t.Fatalf("prevent policy_decision lacks id or hash: %+v", events[0])
	}

	// Hold still queues.
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postTool(t, px, "write_file")
		done <- out
	}()
	var id string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
			break
		}
	}
	if id == "" {
		t.Fatal("prevent hold never appeared in approval queue")
	}
	if !px.Approvals().Decide(id, false, "tester") {
		t.Fatal("decide failed")
	}
	out = <-done
	if errObj, ok := out["error"].(map[string]any); !ok || !strings.Contains(errObj["message"].(string), "denied by approver") {
		t.Fatalf("denied hold should report the approver denial, got %v", out)
	}
}

func TestProxyPreventContainAndPropose(t *testing.T) {
	px, _ := testProxyWithPolicy(t, preventPolicyYAML)
	// Contain still freezes.
	_, out := postTool(t, px, "drop_table")
	if errObj, ok := out["error"].(map[string]any); !ok || !strings.Contains(errObj["message"].(string), "contained") {
		t.Fatalf("prevent contain should block, got %v", out)
	}
	if !px.IsContained("test-session", "") {
		t.Fatal("prevent contain did not freeze the session")
	}
	// A frozen session stays blocked. The containment gate
	// answers with a plain 403, not a JSON-RPC error.
	code, _ := postTool(t, px, "read_file")
	if code != http.StatusForbidden {
		t.Fatalf("call from a contained session should get 403, got %d", code)
	}
}

func TestProxyPreventProposeQueues(t *testing.T) {
	px, _ := testProxyWithPolicy(t, preventPolicyYAML)
	code, out := postTool(t, px, "deploy")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("prevent propose should answer with a result, got %v", out)
	}
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("prevent propose result should be an error, got %v", result)
	}
	if len(px.Proposals().List()) != 1 {
		t.Fatalf("prevent propose should queue one proposal, got %d", len(px.Proposals().List()))
	}
}

func TestHookDetectDenyAllows(t *testing.T) {
	p := hookPolicy(t, `
version: 1
rules:
  - tool: bash
    action: deny
    mode: detect
`)
	px, err := New("http://localhost:1", ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	code, out := postHook(t, px, "bash", `{"command":"rm -rf /"}`, "s1", "")
	if code != http.StatusOK || out["decision"] != "allow" {
		t.Fatalf("detected deny should allow, got %d %v", code, out)
	}
	events, err := px.Ledger().EventsBySession("s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 ledger events, got %d: %+v", len(events), events)
	}
	pd, tc := events[0], events[1]
	if pd.Kind != "policy_decision" || pd.Decision != "deny" || pd.Mode != "detect" || pd.DecisionID == "" || pd.PolicyHash != p.Hash() {
		t.Fatalf("policy_decision = %+v, want deny/detect with id and policy hash", pd)
	}
	if tc.Kind != "tool_call" || tc.Decision != "allow" || tc.Mode != "detect" || tc.DecisionID != pd.DecisionID {
		t.Fatalf("tool_call = %+v, want allow/detect with the same id", tc)
	}
}

func TestHookDetectHoldContainProposeAllow(t *testing.T) {
	cases := []struct {
		action string
		tool   string
	}{
		{"hold", "bash"},
		{"contain", "bash"},
		{"propose", "bash"},
	}
	for _, c := range cases {
		p := hookPolicy(t, "version: 1\nrules:\n  - tool: bash\n    action: "+c.action+"\n    mode: detect\n")
		px, err := New("http://localhost:1", ledger.New(), p)
		if err != nil {
			t.Fatal(err)
		}
		code, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
		if code != http.StatusOK || out["decision"] != "allow" {
			t.Fatalf("%s in detect should allow, got %d %v", c.action, code, out)
		}
		if len(px.Approvals().List()) != 0 {
			t.Fatalf("%s in detect queued an approval", c.action)
		}
		if len(px.Proposals().List()) != 0 {
			t.Fatalf("%s in detect entered the proposal queue", c.action)
		}
		if px.IsContained("s1", "") {
			t.Fatalf("%s in detect froze the session", c.action)
		}
		events, err := px.Ledger().EventsBySession("s1")
		if err != nil {
			t.Fatal(err)
		}
		if len(events) < 2 {
			t.Fatalf("%s in detect should record at least 2 events, got %d", c.action, len(events))
		}
		pd := events[0]
		if pd.Kind != "policy_decision" || pd.Decision != c.action || pd.Mode != "detect" || pd.DecisionID == "" {
			t.Fatalf("policy_decision = %+v, want %s/detect with id", pd, c.action)
		}
		tc := events[len(events)-1]
		if tc.Kind != "tool_call" || tc.Decision != "allow" || tc.DecisionID != pd.DecisionID {
			t.Fatalf("tool_call = %+v, want allow with the same id", tc)
		}
		if c.action == "propose" {
			if len(events) != 3 {
				t.Fatalf("propose in detect should record 3 events, got %d", len(events))
			}
			pr := events[1]
			if pr.Kind != "proposal" || pr.Mode != "detect" || pr.DecisionID != pd.DecisionID {
				t.Fatalf("proposal = %+v, want mode detect with the same id", pr)
			}
		}
	}
}
