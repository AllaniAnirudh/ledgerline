// Command ledgerline runs the trust boundary for AI agents.
//
// Subcommands:
//
//	gateway    run the MCP boundary gateway (witness + policy in-path)
//	approvals  list tool calls currently held for approval
//	approve    approve a held call: ledgerline approve <id>
//	deny       deny a held call:    ledgerline deny <id>
//	export     export the ledger (or one session) as an offline bundle
//	verify     verify an exported bundle's chain without host access
//	run        run a command under PTY capture into the ledger:
//	           ledgerline run --session demo -- echo hello
//
// Quickstart:
//
//	ledgerline gateway --upstream http://localhost:3000 --listen :8080 \
//	  --deny "exec,rm" --hold "write_file"
//
// Point your MCP client at http://localhost:8080. Held calls wait for
// `ledgerline approve <id>`; the replay viewer lives at /replay.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/gateway"
	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
	"github.com/AllaniAnirudh/ledgerline/internal/pty"
	"github.com/AllaniAnirudh/ledgerline/internal/replay"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "gateway":
		err = runGateway(os.Args[2:])
	case "approvals":
		err = runApprovals(os.Args[2:])
	case "approve":
		err = runDecide(os.Args[2:], true)
	case "deny":
		err = runDecide(os.Args[2:], false)
	case "export":
		err = runExport(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "run":
		err = runPTY(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ledgerline <gateway|approvals|approve|deny|export|verify|run> [flags]")
}

// openStore returns the ledger backend: SQLite when --db is set,
// in-memory otherwise.
func openStore(dbPath string) (ledger.Store, func(), error) {
	if dbPath == "" {
		return ledger.New(), func() {}, nil
	}
	s, err := ledger.OpenSQLite(dbPath)
	if err != nil {
		return nil, nil, err
	}
	return s, func() { s.Close() }, nil
}

func runGateway(args []string) error {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	listen := fs.String("listen", ":8080", "address to listen on")
	upstream := fs.String("upstream", "", "upstream MCP server base URL (required)")
	dbPath := fs.String("db", "", "SQLite ledger path (empty = in-memory)")
	deny := fs.String("deny", "", "comma-separated tool names to deny")
	hold := fs.String("hold", "", "comma-separated tool names to hold for approval")
	policyFile := fs.String("policy", "", "YAML policy file (replaces --deny/--hold)")
	apiToken := fs.String("api-token", os.Getenv("LEDGERLINE_API_TOKEN"), "token guarding the /v1 control plane (or env LEDGERLINE_API_TOKEN)")
	var approverTokens stringListFlag
	fs.Var(&approverTokens, "approver-token", "per-approver token as name=token (repeatable); decisions made with it are recorded under that name")
	holdTimeout := fs.Duration("hold-timeout", 5*time.Minute, "how long a held call waits for a human")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *upstream == "" {
		return fmt.Errorf("missing required --upstream")
	}
	if *policyFile != "" && (*deny != "" || *hold != "") {
		return fmt.Errorf("--policy replaces --deny/--hold; pass one or the other, not both")
	}

	store, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()

	var p *policy.Policy
	policyDesc := "static lists"
	if *policyFile != "" {
		p, err = policy.LoadFile(*policyFile)
		if err != nil {
			return err
		}
		if len(p.Rules()) == 0 {
			return fmt.Errorf("policy file %s contains no rules; refusing to start an unpoliced gateway", *policyFile)
		}
		policyDesc = fmt.Sprintf("%s (%d rules, default %s)", *policyFile, len(p.Rules()), p.Default())
	} else {
		p = policy.New(split(*deny), split(*hold))
	}
	px, err := gateway.New(*upstream, store, p)
	if err != nil {
		return err
	}
	px.Approvals().SetTimeout(*holdTimeout)
	if *apiToken != "" {
		px.SetAPIToken(*apiToken)
	}
	for _, pair := range approverTokens {
		name, token, ok := strings.Cut(pair, "=")
		if !ok || name == "" || token == "" {
			return fmt.Errorf("--approver-token must be name=token, got %q", pair)
		}
		px.SetApproverToken(name, token)
	}

	backend := "in-memory"
	if *dbPath != "" {
		backend = *dbPath
	}
	log.Printf("ledgerline: boundary up on %s -> %s (ledger: %s, policy: %s)", *listen, *upstream, backend, policyDesc)
	log.Printf("ledgerline: approvals page at http://localhost%s/approvals, replay at /replay", *listen)
	srv := &http.Server{Addr: *listen, Handler: px, ReadHeaderTimeout: 10 * time.Second}
	return srv.ListenAndServe()
}

// stringListFlag collects a repeatable string flag.
type stringListFlag []string

func (s *stringListFlag) String() string { return strings.Join(*s, ",") }
func (s *stringListFlag) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runApprovals(args []string) error {
	fs := flag.NewFlagSet("approvals", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	watch := fs.Bool("watch", false, "keep polling and print the queue as it changes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	printQueue := func() (string, error) {
		list, err := fetchApprovals(*gw, *token)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		if len(list) == 0 {
			b.WriteString("no pending approvals\n")
		}
		for _, p := range list {
			held := ""
			if ts, ok := p["created_at"].(string); ok {
				if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
					held = fmt.Sprintf("  held=%s", time.Since(t).Round(time.Second))
				}
			}
			argsStr := ""
			if a, ok := p["args"]; ok && a != nil {
				raw, _ := json.Marshal(a)
				s := string(raw)
				if len(s) > 90 {
					s = s[:90] + "..."
				}
				argsStr = "  args=" + s
			}
			fmt.Fprintf(&b, "%s  session=%v  tool=%v%s%s\n", p["id"], p["session_id"], p["tool"], held, argsStr)
		}
		return b.String(), nil
	}
	out, err := printQueue()
	if err != nil {
		return err
	}
	fmt.Print(out)
	if !*watch {
		return nil
	}
	fmt.Println("watching for changes (Ctrl-C to stop)...")
	for {
		time.Sleep(2 * time.Second)
		next, err := printQueue()
		if err != nil {
			return err
		}
		if next != out {
			out = next
			fmt.Print(out)
		}
	}
}

func fetchApprovals(gw, token string) ([]map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(gw, "/")+"/v1/approvals", nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("X-Ledgerline-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway: %s", strings.TrimSpace(string(body)))
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

func runDecide(args []string, approve bool) error {
	name := "approve"
	if !approve {
		name = "deny"
	}
	// Pull the approval ID (first non-flag arg) so flags may come in any
	// order; Go's flag package stops parsing at the first positional arg.
	// Flag values are skipped, not mistaken for the ID.
	valued := map[string]bool{"gateway": true, "actor": true, "token": true}
	var id string
	var rest []string
	skipNext := false
	for _, a := range args {
		if skipNext {
			rest = append(rest, a)
			skipNext = false
			continue
		}
		name := strings.TrimLeft(a, "-")
		if eq := strings.Index(name, "="); eq >= 0 {
			name = name[:eq]
		}
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			if valued[name] && !strings.Contains(a, "=") {
				skipNext = true
			}
			continue
		}
		if id == "" {
			id = a
			continue
		}
		rest = append(rest, a)
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	actor := fs.String("actor", defaultActor(), "who is deciding")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: ledgerline %s <approval-id>", name)
	}
	decision := "deny"
	if approve {
		decision = "approve"
	}
	body, _ := json.Marshal(map[string]string{"decision": decision, "actor": *actor})
	url := strings.TrimSuffix(*gw, "/") + "/v1/approvals/" + id + "/decision"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if *token != "" {
		req.Header.Set("X-Ledgerline-Token", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	past := "denied"
	if approve {
		past = "approved"
	}
	fmt.Printf("%s %s by %s\n", past, id, *actor)
	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite ledger path (empty = in-memory, which exports nothing)")
	out := fs.String("out", "bundle.jsonl", "output bundle path")
	session := fs.String("session", "", "export one session only (empty = whole ledger)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()
	if *session == "" {
		err = replay.ExportJSONL(store, *out)
	} else {
		err = replay.ExportSessionJSONL(store, *session, *out)
	}
	if err != nil {
		return err
	}
	fmt.Println("wrote", *out)
	return nil
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ledgerline verify <bundle.jsonl>")
	}
	if err := replay.VerifyBundle(fs.Arg(0)); err != nil {
		return fmt.Errorf("bundle INVALID: %w", err)
	}
	fmt.Println("bundle valid: chain intact")
	return nil
}

// runPTY runs a command under PTY capture, witnessing its terminal
// output into the ledger under one session id. Shares the SQLite db
// with the gateway, so boundary events and terminal output land on
// one timeline.
func runPTY(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite ledger path (empty = in-memory)")
	sessionID := fs.String("session", "", "session id (default: run-<timestamp>)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("usage: ledgerline run [--db path] [--session id] -- <command> [args...]")
	}
	if *sessionID == "" {
		*sessionID = fmt.Sprintf("run-%d", time.Now().Unix())
	}

	store, closeStore, err := openStore(*dbPath)
	if err != nil {
		return err
	}
	defer closeStore()

	s, err := pty.Start(store, *sessionID, fs.Arg(0), fs.Args()[1:]...)
	if err != nil {
		return err
	}
	defer s.Close()

	// Mirror terminal output locally and pipe stdin through.
	s.OnOutput(func(b []byte) { os.Stdout.Write(b) })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				s.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	fmt.Fprintf(os.Stderr, "ledgerline: captured session %s (pty)\n", *sessionID)
	_ = s.Wait()
	return nil
}

func defaultActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "operator"
}

func split(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return strings.Split(s, ",")
}
