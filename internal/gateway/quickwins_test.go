package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// testProxyPolicy builds a proxy over a counting upstream. The
// counter proves a call never passed the boundary.
func testProxyPolicy(t *testing.T, p *policy.Policy) (*Proxy, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)

	px, err := New(upstream.URL, ledger.New(), p)
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)
	return px, &hits
}

func mustPolicy(t *testing.T, yaml string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestContainActionFreezesSession(t *testing.T) {
	p := mustPolicy(t, `version: 1
default: allow
rules:
  - tool: rm
    action: contain
    reason: "destructive tool"
`)
	px, _ := testProxyPolicy(t, p)

	_, out := postTool(t, px, "rm")
	errObj, ok := out["error"].(map[string]any)
	if !ok || !strings.Contains(errObj["message"].(string), "contained") {
		t.Fatalf("contain rule should error with contained, got %v", out)
	}

	// The session is now frozen. Even allowed tools are refused.
	code, _ := postTool(t, px, "read_file")
	if code != http.StatusForbidden {
		t.Fatalf("contained session should get 403, got %d", code)
	}

	events, _ := px.Ledger().EventsBySession("test-session")
	var sawContain bool
	for _, e := range events {
		if e.Kind == "containment" && e.Decision == "contain" {
			sawContain = true
		}
	}
	if !sawContain {
		t.Fatal("containment not recorded in ledger")
	}
	if list := px.ContainedList(); len(list) != 1 || list[0].SessionID != "test-session" {
		t.Fatalf("contained list wrong: %+v", list)
	}
}

func TestContainDeniesPendingHolds(t *testing.T) {
	px, _ := testProxy(t) // write_file holds, exec denies

	done := make(chan map[string]any, 1)
	go func() {
		_, out := postTool(t, px, "write_file")
		done <- out
	}()

	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if len(px.Approvals().List()) > 0 {
			break
		}
	}
	if len(px.Approvals().List()) == 0 {
		t.Fatal("held call never appeared")
	}

	px.Contain("test-session", "tester", "suspicious hold")
	out := <-done
	errObj, ok := out["error"].(map[string]any)
	if !ok || !strings.Contains(errObj["message"].(string), "denied") {
		t.Fatalf("held call should be denied on contain, got %v", out)
	}
	if len(px.Approvals().List()) != 0 {
		t.Fatal("hold queue should be empty after contain")
	}
}

func TestContainAPI(t *testing.T) {
	px, _ := testProxy(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/sessions/test-session/contain", strings.NewReader(`{"actor":"tester","reason":"manual"}`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("contain API should return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !px.IsContained("test-session", "") {
		t.Fatal("session should be contained after API call")
	}
	req = httptest.NewRequest(http.MethodGet, "/v1/contained", nil)
	rec = httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "test-session") {
		t.Fatalf("contained list should include session, got %s", rec.Body.String())
	}
}

func TestProposeRecordsNotForwards(t *testing.T) {
	p := mustPolicy(t, `version: 1
default: allow
rules:
  - tool: deploy
    action: propose
`)
	px, hits := testProxyPolicy(t, p)

	_, out := postTool(t, px, "deploy")
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("propose should return a result, got %v", out)
	}
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Fatalf("propose result should be marked error (not executed), got %v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("propose result should carry explanatory text, got %v", result)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "NOT executed") {
		t.Fatalf("propose text should say NOT executed, got %q", text)
	}
	if hits.Load() != 0 {
		t.Fatalf("proposed call must never reach upstream, got %d hits", hits.Load())
	}

	list := px.Proposals().List()
	if len(list) != 1 || list[0].Tool != "deploy" {
		t.Fatalf("proposal queue wrong: %+v", list)
	}

	// Apply through the control plane. The proposal is recorded,
	// never forwarded.
	body := `{"decision":"apply","actor":"tester"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+list[0].ID+"/decision", strings.NewReader(body))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply should return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if hits.Load() != 0 {
		t.Fatalf("apply must not forward either, got %d hits", hits.Load())
	}
	if len(px.Proposals().List()) != 0 {
		t.Fatal("proposal queue should be empty after apply")
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	var sawPropose, sawApply bool
	for _, e := range events {
		if e.Kind == "proposal" && e.Decision == "propose" {
			sawPropose = true
		}
		if e.Kind == "proposal" && e.Decision == "apply" && e.Actor == "tester" {
			sawApply = true
		}
	}
	if !sawPropose || !sawApply {
		t.Fatalf("proposal lifecycle not recorded (propose=%v apply=%v)", sawPropose, sawApply)
	}

	// Deciding twice fails.
	if _, ok := px.Proposals().Decide(list[0].ID); ok {
		t.Fatal("second decision on a proposal should fail")
	}
}

func TestProposeDeny(t *testing.T) {
	p := mustPolicy(t, `version: 1
default: allow
rules:
  - tool: deploy
    action: propose
`)
	px, _ := testProxyPolicy(t, p)
	if _, err := px.ledger.Append("test-session", "proposal", "deploy", json.RawMessage(`{}`), "propose", ""); err != nil {
		t.Fatal(err)
	}
	pr, isNew, err := px.proposals.AddDedup("test-session", "deploy", json.RawMessage(`{}`))
	if err != nil || !isNew {
		t.Fatal(err, isNew)
	}
	body := `{"decision":"deny","actor":"tester"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/proposals/"+pr.ID+"/decision", strings.NewReader(body))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny should return 200, got %d: %s", rec.Code, rec.Body.String())
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	var sawDeny bool
	for _, e := range events {
		if e.Kind == "proposal" && e.Decision == "deny" {
			sawDeny = true
		}
	}
	if !sawDeny {
		t.Fatal("proposal deny not recorded")
	}
}

func TestUpstreamPin(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "upstream.pin")
	upstream := "http://localhost:3001"

	st, err := CheckUpstreamPin(pinFile, upstream, false)
	if err != nil || st != "created" {
		t.Fatalf("first run should create pin, got %q %v", st, err)
	}
	st, err = CheckUpstreamPin(pinFile, upstream, false)
	if err != nil || st != "ok" {
		t.Fatalf("same upstream should verify, got %q %v", st, err)
	}
	if _, err := CheckUpstreamPin(pinFile, "http://localhost:3002", false); err == nil {
		t.Fatal("changed upstream without reapprove should fail")
	}
	st, err = CheckUpstreamPin(pinFile, "http://localhost:3002", true)
	if err != nil || st != "reapproved" {
		t.Fatalf("reapprove should overwrite pin, got %q %v", st, err)
	}
	raw, _ := os.ReadFile(pinFile)
	if strings.TrimSpace(string(raw)) != UpstreamPin("http://localhost:3002") {
		t.Fatalf("pin file should hold new pin, got %q", strings.TrimSpace(string(raw)))
	}
	// A trailing slash is the same upstream after normalization.
	st, err = CheckUpstreamPin(pinFile, "http://localhost:3002/", false)
	if err != nil || st != "ok" {
		t.Fatalf("trailing slash should still verify, got %q %v", st, err)
	}
}
