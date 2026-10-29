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

func postHook(t *testing.T, px *Proxy, tool, args, session, token string) (int, map[string]any) {
	t.Helper()
	body := `{"tool":"` + tool + `","arguments":` + args + `,"session":"` + session + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/hook", strings.NewReader(body))
	if token != "" {
		req.Header.Set("X-Ledgerline-Token", token)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func hookPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHookAllow(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	code, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
	if code != http.StatusOK || out["decision"] != "allow" {
		t.Fatalf("allow: want 200/allow, got %d %v", code, out)
	}
	if n := countEvents(t, px, "tool_call", "allow"); n != 1 {
		t.Fatalf("allow should witness one tool_call, got %d", n)
	}
}

func TestHookDeny(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New([]string{"bash"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	code, out := postHook(t, px, "bash", `{"command":"rm -rf /"}`, "s1", "")
	if code != http.StatusOK || out["decision"] != "deny" {
		t.Fatalf("deny: want 200/deny, got %d %v", code, out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "denied by policy") {
		t.Fatalf("deny reason should name policy, got %v", out)
	}
}

func TestHookHoldApprove(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, []string{"bash"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(10 * time.Second)
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
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
	if n := countEvents(t, px, "approval", "approve"); n != 1 {
		t.Fatalf("approve should witness one approval, got %d", n)
	}
}

func TestHookHoldDeny(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, []string{"bash"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(10 * time.Second)
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
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
	if !px.Approvals().Decide(id, false, "tester") {
		t.Fatal("decision should succeed")
	}
	out := <-done
	if out["decision"] != "deny" {
		t.Fatalf("denied hold should deny, got %v", out)
	}
}

func TestHookHoldTimeout(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, []string{"bash"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(100 * time.Millisecond)
	_, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
	if out["decision"] != "deny" {
		t.Fatalf("timed-out hold should deny, got %v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "timed out") {
		t.Fatalf("timeout reason should name the timeout, got %v", out)
	}
}

func TestHookContain(t *testing.T) {
	p := hookPolicy(t, "version: 1\nrules:\n  - tool: bash\n    action: contain\n")
	px, err := New("http://localhost:1", ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	_, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
	if out["decision"] != "deny" {
		t.Fatalf("contain should deny, got %v", out)
	}
	if !px.IsContained("s1", "") {
		t.Fatal("contain rule should freeze the session")
	}
}

func TestHookPropose(t *testing.T) {
	p := hookPolicy(t, "version: 1\nrules:\n  - tool: bash\n    action: propose\n")
	px, err := New("http://localhost:1", ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	_, out := postHook(t, px, "bash", `{"command":"ls"}`, "s1", "")
	if out["decision"] != "deny" {
		t.Fatalf("propose should deny, got %v", out)
	}
	if reason, _ := out["reason"].(string); !strings.Contains(reason, "NOT executed") {
		t.Fatalf("propose reason should say NOT executed, got %v", out)
	}
	if n := countEvents(t, px, "proposal", "propose"); n != 1 {
		t.Fatalf("propose should witness one proposal, got %d", n)
	}
}

func TestHookTokenGate(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.SetAPIToken("tok")
	if code, _ := postHook(t, px, "bash", `{}`, "s1", ""); code != http.StatusUnauthorized {
		t.Fatalf("hook without token: want 401, got %d", code)
	}
	if code, out := postHook(t, px, "bash", `{}`, "s1", "tok"); code != http.StatusOK || out["decision"] != "allow" {
		t.Fatalf("hook with token: want 200/allow, got %d %v", code, out)
	}
}

func TestHookBadBody(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/hook", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed hook body: want 400, got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/hook", strings.NewReader(`{"arguments":{}}`))
	rec = httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("hook body without tool: want 400, got %d", rec.Code)
	}
}

func TestHookContainedSession(t *testing.T) {
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.Contain("s1", "", "test")
	_, out := postHook(t, px, "bash", `{}`, "s1", "")
	if out["decision"] != "deny" {
		t.Fatalf("contained session should deny, got %v", out)
	}
}

func TestHookBrokerSecret(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, "version: 1\ncredentials:\n  - name: upstream-key\n    header: X-Upstream-Key\n    env: LEDGERLINE_TEST_BROKER_KEY\n")
	px, err := New("http://localhost:1", ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.SetBroker(b)
	_, out := postHook(t, px, "bash", `{"command":"`+testSecret+`"}`, "s1", "")
	if out["decision"] != "deny" {
		t.Fatalf("secret in hook arguments should deny, got %v", out)
	}
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(string(e.Args), testSecret) {
			t.Fatal("hook ledger must never record a brokered secret")
		}
	}
}
