package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/gateway"
	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

func TestParseHookPayloadClaude(t *testing.T) {
	p, err := parseHookPayload("claude-code", []byte(`{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"s1","cwd":"/tmp"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "bash" {
		t.Fatalf("Bash should map to bash, got %q", p.Tool)
	}
	if p.Session != "s1" {
		t.Fatalf("session should pass through, got %q", p.Session)
	}
	var args map[string]any
	if err := json.Unmarshal(p.Args, &args); err != nil || args["command"] != "ls" {
		t.Fatalf("tool_input should pass through as args, got %s", p.Args)
	}
}

func TestParseHookPayloadClaudeUnknown(t *testing.T) {
	p, err := parseHookPayload("claude-code", []byte(`{"tool_name":"SomeTool","tool_input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "SomeTool" {
		t.Fatalf("unknown Claude tool should pass through unchanged, got %q", p.Tool)
	}
}

func TestParseHookPayloadClaudeMCP(t *testing.T) {
	p, err := parseHookPayload("claude-code", []byte(`{"tool_name":"mcp__memory__read","tool_input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "mcp__memory__read" {
		t.Fatalf("MCP tool name should pass through, got %q", p.Tool)
	}
}

func TestParseHookPayloadGemini(t *testing.T) {
	p, err := parseHookPayload("gemini", []byte(`{"tool_name":"run_shell_command","tool_input":{"command":"ls"},"session_id":"s1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "bash" {
		t.Fatalf("run_shell_command should map to bash, got %q", p.Tool)
	}
	p, err = parseHookPayload("gemini", []byte(`{"tool_name":"replace","tool_input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "edit" {
		t.Fatalf("replace should map to edit, got %q", p.Tool)
	}
}

func TestParseHookPayloadGeneric(t *testing.T) {
	p, err := parseHookPayload("generic", []byte(`{"tool":"bash","arguments":{"command":"ls"},"session":"s9"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "bash" || p.Session != "s9" {
		t.Fatalf("generic envelope should pass through, got %+v", p)
	}
	p, err = parseHookPayload("opencode", []byte(`{"tool":"edit","args":{"filePath":"a.txt"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "edit" {
		t.Fatalf("opencode tool should pass through, got %q", p.Tool)
	}
}

func TestParseHookPayloadErrors(t *testing.T) {
	if _, err := parseHookPayload("claude-code", []byte(`not json`)); err == nil {
		t.Fatal("malformed payload should error")
	}
	if _, err := parseHookPayload("claude-code", []byte(`{"tool_input":{}}`)); err == nil {
		t.Fatal("payload without tool should error")
	}
	if _, err := parseHookPayload("nope", []byte(`{}`)); err == nil {
		t.Fatal("unknown harness should error")
	}
}

func countStoreEvents(t *testing.T, store ledger.Store, kind, decision string) int {
	t.Helper()
	events, err := store.Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == kind && e.Decision == decision {
			n++
		}
	}
	return n
}

func TestDecideHookStandaloneAllow(t *testing.T) {
	store := ledger.New()
	out := decideHookStandalone(store, policy.New(nil, nil), nil, "s1", "bash", json.RawMessage(`{"command":"ls"}`))
	if !out.allow {
		t.Fatalf("allow policy should allow, got %+v", out)
	}
	if n := countStoreEvents(t, store, "tool_call", "allow"); n != 1 {
		t.Fatalf("allow should witness one tool_call, got %d", n)
	}
}

func TestDecideHookStandaloneDeny(t *testing.T) {
	store := ledger.New()
	out := decideHookStandalone(store, policy.New([]string{"bash"}, nil), nil, "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "denied by policy") {
		t.Fatalf("deny policy should block with reason, got %+v", out)
	}
}

func TestDecideHookStandaloneHold(t *testing.T) {
	store := ledger.New()
	out := decideHookStandalone(store, policy.New(nil, []string{"bash"}), nil, "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "no gateway") {
		t.Fatalf("standalone hold should block with a gateway note, got %+v", out)
	}
	if n := countStoreEvents(t, store, "approval", "hold"); n != 1 {
		t.Fatalf("standalone hold should witness one hold, got %d", n)
	}
}

func TestDecideHookStandaloneContainPropose(t *testing.T) {
	p, err := policy.Parse([]byte("version: 1\nrules:\n  - tool: bash\n    action: contain\n  - tool: edit\n    action: propose\n"))
	if err != nil {
		t.Fatal(err)
	}
	store := ledger.New()
	out := decideHookStandalone(store, p, nil, "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "contained") {
		t.Fatalf("contain should block, got %+v", out)
	}
	out = decideHookStandalone(store, p, nil, "s1", "edit", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "NOT executed") {
		t.Fatalf("propose should block as not executed, got %+v", out)
	}
	if n := countStoreEvents(t, store, "proposal", "propose"); n != 1 {
		t.Fatalf("propose should witness one proposal, got %d", n)
	}
}

func TestDecideHookStandaloneLedgerFailure(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "closed.db")
	store, err := ledger.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	out := decideHookStandalone(store, policy.New(nil, nil), nil, "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "ledger unavailable") {
		t.Fatalf("ledger failure should block, got %+v", out)
	}
}

func TestResolveHoldTimeout(t *testing.T) {
	if d, err := resolveHoldTimeout("gemini", 0); err != nil || d != 25*time.Second {
		t.Fatalf("gemini auto timeout should be 25s, got %v %v", d, err)
	}
	if d, err := resolveHoldTimeout("claude-code", 0); err != nil || d != 120*time.Second {
		t.Fatalf("default auto timeout should be 120s, got %v %v", d, err)
	}
	if d, err := resolveHoldTimeout("gemini", 90*time.Second); err != nil || d != 90*time.Second {
		t.Fatalf("explicit timeout should pass through, got %v %v", d, err)
	}
	if _, err := resolveHoldTimeout("generic", -time.Second); err == nil {
		t.Fatal("negative timeout should error")
	}
}

func TestMapHookNameMCPMixed(t *testing.T) {
	if got := mapHookName("claude-code", "mcp__MyServer__MyTool"); got != "mcp__MyServer__MyTool" {
		t.Fatalf("mixed-case MCP name should pass through, got %q", got)
	}
}

func TestParseHookPayloadGeminiMap(t *testing.T) {
	p, err := parseHookPayload("gemini", []byte(`{"tool_name":"read_many_files","tool_input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "read" {
		t.Fatalf("read_many_files should map to read, got %q", p.Tool)
	}
	p, err = parseHookPayload("gemini", []byte(`{"tool_name":"search_file_content","tool_input":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tool != "search" {
		t.Fatalf("search_file_content should map to search, got %q", p.Tool)
	}
}

func TestDecideHookGateway(t *testing.T) {
	allowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hook" || r.Header.Get("X-Ledgerline-Token") != "tok" {
			t.Errorf("gateway call should hit /v1/hook with the token, got path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer allowSrv.Close()
	out, err := decideHookGateway(allowSrv.URL+"/", "tok", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || !out.allow {
		t.Fatalf("allow answer should allow, got %+v %v", out, err)
	}

	denySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"deny","reason":"nope"}`))
	}))
	defer denySrv.Close()
	out, err = decideHookGateway(denySrv.URL, "", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || out.allow || out.reason != "nope" {
		t.Fatalf("deny answer should block with its reason, got %+v %v", out, err)
	}

	bareDenySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"decision":"deny"}`))
	}))
	defer bareDenySrv.Close()
	out, err = decideHookGateway(bareDenySrv.URL, "", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || out.allow || !strings.Contains(out.reason, "denied by gateway") {
		t.Fatalf("bare deny should use the fallback reason, got %+v %v", out, err)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("ledger unavailable"))
	}))
	defer errSrv.Close()
	if _, err := decideHookGateway(errSrv.URL, "", time.Second, "s1", "bash", json.RawMessage(`{}`)); err == nil {
		t.Fatal("non-200 gateway answer should error")
	}

	badJSONSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer badJSONSrv.Close()
	if _, err := decideHookGateway(badJSONSrv.URL, "", time.Second, "s1", "bash", json.RawMessage(`{}`)); err == nil {
		t.Fatal("undecodable gateway answer should error")
	}

}

func TestHookClientTimeout(t *testing.T) {
	// The total wait is timeout plus 30 seconds of grace.
	// The Gemini default must stay below the 60 second kill
	// line: 25 seconds plus 30 seconds is 55 seconds.
	if got := hookHTTPClient(25 * time.Second).Timeout; got != 55*time.Second {
		t.Fatalf("gemini default wait should be 55s, got %v", got)
	}
	if got := hookHTTPClient(120 * time.Second).Timeout; got != 150*time.Second {
		t.Fatalf("default wait should be 150s, got %v", got)
	}
}

func TestDecideHookStandaloneBroker(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_HOOK_BROKER_KEY", "hook-broker-secret-12345")
	cfg := filepath.Join(t.TempDir(), "broker.yaml")
	if err := os.WriteFile(cfg, []byte("version: 1\ncredentials:\n  - name: upstream-key\n    header: X-Upstream-Key\n    env: LEDGERLINE_TEST_HOOK_BROKER_KEY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := gateway.LoadBrokerFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	store := ledger.New()
	out := decideHookStandalone(store, policy.New(nil, nil), b, "s1", "bash", json.RawMessage(`{"command":"hook-broker-secret-12345"}`))
	if out.allow || !strings.Contains(out.reason, "brokered credential") {
		t.Fatalf("secret in arguments should deny, got %+v", out)
	}
	events, err := store.Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(string(e.Args), "hook-broker-secret-12345") {
			t.Fatal("standalone ledger must never record a brokered secret")
		}
	}
	out = decideHookStandalone(store, policy.New(nil, nil), b, "s1", "bash", json.RawMessage(`{"command":"ls"}`))
	if !out.allow {
		t.Fatalf("clean call should allow, got %+v", out)
	}
}
