package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

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
	if p.Tool != "sometool" {
		t.Fatalf("unknown Claude tool should lowercase, got %q", p.Tool)
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
	out := decideHookStandalone(store, policy.New(nil, nil), "s1", "bash", json.RawMessage(`{"command":"ls"}`))
	if !out.allow {
		t.Fatalf("allow policy should allow, got %+v", out)
	}
	if n := countStoreEvents(t, store, "tool_call", "allow"); n != 1 {
		t.Fatalf("allow should witness one tool_call, got %d", n)
	}
}

func TestDecideHookStandaloneDeny(t *testing.T) {
	store := ledger.New()
	out := decideHookStandalone(store, policy.New([]string{"bash"}, nil), "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "denied by policy") {
		t.Fatalf("deny policy should block with reason, got %+v", out)
	}
}

func TestDecideHookStandaloneHold(t *testing.T) {
	store := ledger.New()
	out := decideHookStandalone(store, policy.New(nil, []string{"bash"}), "s1", "bash", json.RawMessage(`{}`))
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
	out := decideHookStandalone(store, p, "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "contained") {
		t.Fatalf("contain should block, got %+v", out)
	}
	out = decideHookStandalone(store, p, "s1", "edit", json.RawMessage(`{}`))
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
	out := decideHookStandalone(store, policy.New(nil, nil), "s1", "bash", json.RawMessage(`{}`))
	if out.allow || !strings.Contains(out.reason, "ledger unavailable") {
		t.Fatalf("ledger failure should block, got %+v", out)
	}
}
