package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/gateway"
	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// The hook bridge checks native tool calls. A harness calls it
// before each native tool runs. Native tools never cross the MCP
// boundary, so the gateway alone cannot see them.
//
// Exit codes are the whole contract. They are uniform across
// harnesses. Exit 0 allows the call. Exit 2 blocks it, and the
// reason goes to stderr, where the harness shows it to the agent.
// The bridge never exits 1. Claude Code and Gemini CLI treat any
// exit other than 0 or 2 as a non-blocking error. A bridge
// failure must surface as a block, not a crash code.
//
// An allow from the bridge means Ledgerline does not object. It
// does not grant harness permission. The harness still runs its
// own permission flow. A block from the bridge always wins over
// a harness allow rule.
//
// A bridge error blocks, unless --fail-open is set. Fail-open
// flips errors only. A policy denial still blocks.

const maxHookPayload = 10 << 20

// hookNameMaps translate harness tool names to canonical names.
// One policy file then reads the same across harnesses. A name
// with no entry passes through unchanged. For Claude Code,
// unknown names are lowercased to match the built-in style.
var hookNameMaps = map[string]map[string]string{
	"claude-code": {
		"Bash": "bash", "Read": "read", "Edit": "edit", "Write": "write",
		"Glob": "glob", "Grep": "grep", "Task": "task",
		"WebFetch": "webfetch", "WebSearch": "websearch",
		"TodoWrite": "todowrite", "KillShell": "killshell",
		"NotebookEdit": "notebookedit", "ExitPlanMode": "exitplanmode",
		"AskUserQuestion": "askuserquestion",
	},
	"gemini": {
		"run_shell_command": "bash", "read_file": "read",
		"read_many_files": "read", "write_file": "write",
		"replace": "edit", "grep_search": "grep",
		"search_file_content": "search", "web_fetch": "webfetch",
		"web_search": "websearch", "list_directory": "list",
	},
	"opencode": {},
	"generic":  {},
}

type hookPayload struct {
	Tool    string
	Args    json.RawMessage
	Session string
}

func mapHookName(harness, name string) string {
	if m, ok := hookNameMaps[harness]; ok {
		if canonical, ok := m[name]; ok {
			return canonical
		}
	}
	if harness == "claude-code" {
		if strings.HasPrefix(name, "mcp__") {
			return name
		}
		return strings.ToLower(name)
	}
	return name
}

// parseHookPayload reads one harness hook payload. Claude Code and
// Gemini CLI send tool_name, tool_input, and session_id. OpenCode
// plugins and generic callers send tool, args, and session.
func parseHookPayload(harness string, raw []byte) (hookPayload, error) {
	switch harness {
	case "claude-code", "gemini":
		var m struct {
			ToolName  string          `json:"tool_name"`
			ToolInput json.RawMessage `json:"tool_input"`
			SessionID string          `json:"session_id"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return hookPayload{}, fmt.Errorf("bad hook payload: %w", err)
		}
		if strings.TrimSpace(m.ToolName) == "" {
			return hookPayload{}, fmt.Errorf("hook payload has no tool name")
		}
		return hookPayload{Tool: mapHookName(harness, m.ToolName), Args: orEmptyArgs(m.ToolInput), Session: m.SessionID}, nil
	case "opencode", "generic":
		var m struct {
			Tool      string          `json:"tool"`
			Args      json.RawMessage `json:"args"`
			Arguments json.RawMessage `json:"arguments"`
			Session   string          `json:"session"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return hookPayload{}, fmt.Errorf("bad hook payload: %w", err)
		}
		if strings.TrimSpace(m.Tool) == "" {
			return hookPayload{}, fmt.Errorf("hook payload has no tool name")
		}
		args := m.Args
		if len(args) == 0 {
			args = m.Arguments
		}
		return hookPayload{Tool: mapHookName(harness, m.Tool), Args: orEmptyArgs(args), Session: m.Session}, nil
	default:
		return hookPayload{}, fmt.Errorf("unknown harness %q (want claude-code, gemini, opencode, or generic)", harness)
	}
}

func orEmptyArgs(args json.RawMessage) json.RawMessage {
	if len(args) == 0 {
		return json.RawMessage("{}")
	}
	return args
}

// hookOutcome is one bridge answer. Allow means the call may run.
// Reason carries the block message for stderr.
type hookOutcome struct {
	allow  bool
	reason string
}

// resolveHoldTimeout turns an unset hold timeout into a
// per-harness default. Gemini kills hooks at 60 seconds by
// default. Its default sits below that line, so the bridge
// answers before Gemini kills it. Other harnesses get 120
// seconds. A negative value is an error.
func resolveHoldTimeout(harness string, d time.Duration) (time.Duration, error) {
	if d < 0 {
		return 0, fmt.Errorf("--hold-timeout must be zero or above")
	}
	if d > 0 {
		return d, nil
	}
	if harness == "gemini" {
		return 45 * time.Second, nil
	}
	return 120 * time.Second, nil
}

// decideHookStandalone applies the policy without a gateway. It
// mirrors the gateway witness order. The policy decision comes
// first. The call record comes second. A hold cannot wait
// without a gateway. It blocks with a note on how to approve
// and retry. A contain rule keeps denying while it stands.
// Each new hook invocation re-evaluates the policy. A proposal
// is recorded in the ledger. The agent is told the action was
// not executed. With a broker, a brokered secret in the
// arguments is denied before any witness records those
// arguments. Without a broker, arguments are recorded as sent.
func decideHookStandalone(store ledger.Store, pol *policy.Policy, broker *gateway.Broker, session, tool string, args json.RawMessage) hookOutcome {
	if broker != nil && broker.ContainsSecret(args) {
		if _, err := store.Append(session, "policy_decision", tool, nil, "deny", ""); err != nil {
			return hookOutcome{reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookOutcome{reason: "ledgerline: tool arguments contain a brokered credential"}
	}
	decision, reason := pol.DecideCall(tool, args)
	if _, err := store.Append(session, "policy_decision", tool, nil, decision.String(), ""); err != nil {
		return hookOutcome{reason: "ledgerline: ledger unavailable, boundary closed"}
	}
	switch decision {
	case policy.Allow:
		if _, err := store.Append(session, "tool_call", tool, args, "allow", ""); err != nil {
			return hookOutcome{reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookOutcome{allow: true}
	case policy.Deny:
		msg := "ledgerline: tool call denied by policy"
		if reason != "" {
			msg += ": " + reason
		}
		return hookOutcome{reason: msg}
	case policy.Contain:
		msg := "ledgerline: session contained by policy"
		if reason != "" {
			msg += ": " + reason
		}
		return hookOutcome{reason: msg}
	case policy.Propose:
		if _, err := store.Append(session, "proposal", tool, args, "propose", ""); err != nil {
			return hookOutcome{reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookOutcome{reason: "ledgerline: action NOT executed; recorded in the ledger for human application out of band"}
	case policy.Hold:
		if _, err := store.Append(session, "approval", tool, args, "hold", ""); err != nil {
			return hookOutcome{reason: "ledgerline: ledger unavailable, boundary closed"}
		}
		return hookOutcome{reason: "ledgerline: held for approval, but no gateway is set. Change the policy to allow it, or run a gateway and approve there, then try again"}
	default:
		return hookOutcome{reason: "ledgerline: unknown policy decision"}
	}
}

// decideHookGateway asks a running gateway. The gateway applies
// policy, records the call, and waits out a hold. A transport
// error or a bad answer is a bridge error, not a policy denial.
func decideHookGateway(gwURL, token string, timeout time.Duration, session, tool string, args json.RawMessage) (hookOutcome, error) {
	body, _ := json.Marshal(map[string]any{"tool": tool, "arguments": args, "session": session})
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(gwURL, "/")+"/v1/hook", bytes.NewReader(body))
	if err != nil {
		return hookOutcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Ledgerline-Token", token)
	}
	client := &http.Client{Timeout: timeout + 30*time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return hookOutcome{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return hookOutcome{}, fmt.Errorf("gateway: %s", strings.TrimSpace(string(raw)))
	}
	var dec struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &dec); err != nil {
		return hookOutcome{}, fmt.Errorf("bad gateway answer: %w", err)
	}
	if dec.Decision == "allow" {
		return hookOutcome{allow: true}, nil
	}
	reason := dec.Reason
	if reason == "" {
		reason = "ledgerline: tool call denied by gateway"
	}
	return hookOutcome{reason: reason}, nil
}

// runHook never returns a plain error. Every failure path prints
// its reason to stderr and returns exit code 2. The harness then
// blocks. Main maps exitCodeError to the process exit code.
func runHook(args []string) error {
	fs := flag.NewFlagSet("hook", flag.ExitOnError)
	harness := fs.String("harness", "claude-code", "hook payload shape: claude-code, gemini, opencode, or generic")
	policyFile := fs.String("policy", "", "YAML policy file (replaces --deny/--hold)")
	deny := fs.String("deny", "", "comma-separated tool names to deny")
	hold := fs.String("hold", "", "comma-separated tool names to hold for approval")
	dbPath := fs.String("db", "", "SQLite ledger path (empty = in-memory)")
	gatewayURL := fs.String("gateway", "", "running gateway base URL (when set, decisions come from the gateway; --db is ignored)")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	sessionFlag := fs.String("session", "", "ledger session (default: the harness session id)")
	holdTimeout := fs.Duration("hold-timeout", 0, "how long to wait for a gateway approval before denying (0 = auto: 120s, or 45s for gemini; the bridge waits this plus 30s of client grace)")
	brokerFile := fs.String("broker", "", "broker config file for standalone secret scans (empty = no scan; values come from the environment, never the file)")
	failOpen := fs.Bool("fail-open", false, "allow on bridge errors (policy denials still block)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	block := func(reason string) error {
		fmt.Fprintln(os.Stderr, reason)
		return exitCodeError{code: 2}
	}
	if *policyFile != "" && (*deny != "" || *hold != "") {
		return block("ledgerline hook: --policy replaces --deny/--hold; pass one or the other, not both")
	}
	timeout, err := resolveHoldTimeout(*harness, *holdTimeout)
	if err != nil {
		return block("ledgerline hook: " + err.Error())
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxHookPayload+1))
	if err != nil {
		return block("ledgerline hook: cannot read hook payload")
	}
	if len(raw) > maxHookPayload {
		return block("ledgerline hook: hook payload too large")
	}
	payload, err := parseHookPayload(*harness, raw)
	if err != nil {
		return block("ledgerline hook: " + err.Error())
	}
	session := *sessionFlag
	if session == "" {
		session = payload.Session
	}
	if session == "" {
		session = "default"
	}

	var outcome hookOutcome
	if *gatewayURL != "" {
		outcome, err = decideHookGateway(*gatewayURL, *token, timeout, session, payload.Tool, payload.Args)
		if err != nil {
			if *failOpen {
				fmt.Fprintf(os.Stderr, "ledgerline hook: fail-open: %v\n", err)
				return nil
			}
			return block("ledgerline hook: " + err.Error())
		}
	} else {
		var pol *policy.Policy
		if *policyFile != "" {
			pol, err = policy.LoadFile(*policyFile)
			if err != nil {
				return block("ledgerline hook: " + err.Error())
			}
			if len(pol.Rules()) == 0 {
				return block("ledgerline hook: policy file contains no rules; refusing to start an unpoliced bridge")
			}
		} else {
			pol = policy.New(split(*deny), split(*hold))
		}
		var broker *gateway.Broker
		if *brokerFile != "" {
			broker, err = gateway.LoadBrokerFile(*brokerFile)
			if err != nil {
				return block("ledgerline hook: " + err.Error())
			}
		}
		store, closeStore, err := openStore(*dbPath)
		if err != nil {
			return block("ledgerline hook: " + err.Error())
		}
		defer closeStore()
		outcome = decideHookStandalone(store, pol, broker, session, payload.Tool, payload.Args)
	}
	if outcome.allow {
		return nil
	}
	return block(outcome.reason)
}
