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

func testProxy(t *testing.T) (*Proxy, *httptest.Server) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)

	px, err := New(upstream.URL, ledger.New(), policy.New([]string{"exec"}, []string{"write_file"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)
	return px, upstream
}

func postTool(t *testing.T, px *Proxy, tool string) (int, map[string]any) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)

	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestAllowForwards(t *testing.T) {
	px, _ := testProxy(t)
	code, out := postTool(t, px, "read_file")
	if code != 200 {
		t.Fatalf("want 200, got %d", code)
	}
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("allowed call got error: %v", out["error"])
	}
	events, _ := px.Ledger().EventsBySession("test-session")
	if len(events) != 2 { // policy_decision + tool_call
		t.Fatalf("want 2 ledger events, got %d", len(events))
	}
}

func TestDenyBlocks(t *testing.T) {
	px, _ := testProxy(t)
	_, out := postTool(t, px, "exec")
	errObj, ok := out["error"].(map[string]any)
	if !ok {
		t.Fatalf("denied call should return JSON-RPC error, got %v", out)
	}
	if !strings.Contains(errObj["message"].(string), "denied") {
		t.Fatalf("unexpected error message: %v", errObj["message"])
	}
}

func TestHoldApprovesAndForwards(t *testing.T) {
	px, _ := testProxy(t)

	done := make(chan map[string]any, 1)
	go func() {
		_, out := postTool(t, px, "write_file")
		done <- out
	}()

	// Wait for the hold to appear, then approve it.
	var id string
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
			break
		}
	}
	if id == "" {
		t.Fatal("held call never appeared in approval queue")
	}
	if !px.Approvals().Decide(id, true, "tester") {
		t.Fatal("decide failed")
	}

	out := <-done
	if _, hasErr := out["error"]; hasErr {
		t.Fatalf("approved call got error: %v", out["error"])
	}
	if out["result"] == nil {
		t.Fatalf("approved call should return upstream result, got %v", out)
	}

	events, _ := px.Ledger().EventsBySession("test-session")
	var sawApproval bool
	for _, e := range events {
		if e.Kind == "approval" && e.Decision == "approve" {
			sawApproval = true
		}
	}
	if !sawApproval {
		t.Fatal("approval not recorded in ledger")
	}
}

func TestHoldTimeoutDenies(t *testing.T) {
	px, _ := testProxy(t)
	px.Approvals().SetTimeout(100 * time.Millisecond)
	_, out := postTool(t, px, "write_file")
	errObj, ok := out["error"].(map[string]any)
	if !ok || !strings.Contains(errObj["message"].(string), "timed out") {
		t.Fatalf("want timeout error, got %v", out)
	}
}
