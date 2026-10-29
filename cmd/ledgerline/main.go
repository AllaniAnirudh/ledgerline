// Command ledgerline runs the trust boundary for AI agents.
//
// Subcommands:
//
//	gateway    run the MCP boundary gateway (witness + policy in-path,
//	           with an optional credential broker: --broker broker.yaml)
//	approvals  list tool calls currently held for approval
//	approve    approve a held call: ledgerline approve <id>
//	deny       deny a held call or a proposal: ledgerline deny <id>
//	contain    freeze a session:    ledgerline contain <session-id>
//	contained  list frozen sessions
//	proposals  list actions proposed for out-of-band application
//	apply      record a proposal as applied out of band:
//	           ledgerline apply <proposal-id>
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
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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
	case "contain":
		err = runContain(os.Args[2:])
	case "contained":
		err = runContained(os.Args[2:])
	case "proposals":
		err = runProposals(os.Args[2:])
	case "apply":
		err = runApply(os.Args[2:])
	case "idempotency":
		err = runIdempotency(os.Args[2:])
	case "resolve":
		err = runResolve(os.Args[2:])
	case "tools":
		err = runTools(os.Args[2:])
	case "accept-tools":
		err = runAcceptTools(os.Args[2:])
	case "export":
		err = runExport(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "run":
		err = runPTY(os.Args[2:])
	case "hook":
		err = runHook(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		var ec exitCodeError
		if errors.As(err, &ec) {
			os.Exit(ec.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ledgerline <gateway|approvals|approve|deny|contain|contained|proposals|apply|idempotency|resolve|tools|accept-tools|export|verify|run|hook> [flags]")
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
	pinFile := fs.String("upstream-pin-file", "", "path to the upstream pin file (empty = no pinning; first run creates the pin)")
	brokerFile := fs.String("broker", "", "broker config file (empty = no broker; credential values come from the environment, never the file)")
	reapprove := fs.Bool("reapprove-upstream", false, "accept a changed upstream and overwrite the pin (witnessed in the ledger)")
	reapproveActor := fs.String("reapprove-actor", defaultActor(), "who is re-approving the upstream")
	reapproveTools := fs.Bool("reapprove-tools", false, "accept the next observed tool surface as the new baseline (witnessed in the ledger)")
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
	if *brokerFile != "" {
		b, err := gateway.LoadBrokerFile(*brokerFile)
		if err != nil {
			return err
		}
		px.SetBroker(b)
		var names []string
		for _, s := range b.Status() {
			names = append(names, s.Name)
		}
		log.Printf("ledgerline: broker active (%d credentials: %s)", len(names), strings.Join(names, ", "))
	}
	if *pinFile != "" {
		st, err := gateway.CheckUpstreamPin(*pinFile, *upstream, *reapprove)
		if err != nil {
			return err
		}
		pin := gateway.UpstreamPin(*upstream)
		px.SetUpstreamPin(pin)
		switch st {
		case "created":
			log.Printf("ledgerline: upstream pin created for %s", gateway.RedactURL(*upstream))
		case "ok":
			log.Printf("ledgerline: upstream pin verified for %s", gateway.RedactURL(*upstream))
		case "reapproved":
			argsJSON, _ := json.Marshal(map[string]string{"pin": pin})
			if _, err := store.Append("gateway", "upstream", "(upstream)", argsJSON, "reapprove", *reapproveActor); err != nil {
				log.Printf("ledgerline: WARNING: could not witness upstream re-approval: %v", err)
			}
			log.Printf("ledgerline: upstream pin re-approved for %s by %s", gateway.RedactURL(*upstream), *reapproveActor)
		}
	}
	if *reapproveTools {
		px.SetToolsReapprovePending(*reapproveActor)
	}
	if err := px.ProbeToolsBaseline(); err != nil {
		return err
	}
	if !px.HasToolsBaseline() {
		// The upstream was not up (or not listable) at startup.
		// A one-shot probe would leave the gateway anchorless
		// until the agent's first list, which could itself be
		// post-compromise. Retry quietly until a baseline
		// exists; the first passthrough list also establishes
		// one, whichever comes first.
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				if px.HasToolsBaseline() {
					return
				}
				if err := px.ProbeToolsBaselineQuiet(); err != nil {
					log.Printf("tools baseline retry failed: %v", err)
					return
				}
				if px.HasToolsBaseline() {
					log.Printf("ledgerline: tool baseline established by retry probe")
					return
				}
			}
		}()
	}
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
	if *apiToken == "" && len(approverTokens) == 0 {
		log.Printf("ledgerline: WARNING: no API token set. The control plane is unauthenticated: anyone who can reach %s can read the ledger (arguments included), decide approvals, and accept a new tool surface (drift re-baseline). Set --api-token or --approver-token before exposing this port beyond loopback.", *listen)
	}
	log.Printf("ledgerline: boundary up on %s -> %s (ledger: %s, policy: %s)", *listen, gateway.RedactURL(*upstream), backend, policyDesc)
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
		// A deny for an unknown approval may be a proposal: deny
		// falls through to the proposal queue before giving up.
		// Approve has no fallback: proposals are applied, not
		// approved, but a miss that turns out to be a proposal
		// says so instead of leaving a bare 404.
		if resp.StatusCode == http.StatusNotFound {
			if !approve {
				if err := denyProposal(*gw, id, *actor, *token); err == nil {
					fmt.Printf("denied %s by %s\n", id, *actor)
					return nil
				}
			} else if list, err := fetchProposals(*gw, *token); err == nil {
				for _, p := range list {
					if p["id"] == id {
						return fmt.Errorf("id %s is a proposal, not a held call; use 'ledgerline apply %s'", id, id)
					}
				}
			}
		}
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	past := "denied"
	if approve {
		past = "approved"
	}
	fmt.Printf("%s %s by %s\n", past, id, *actor)
	return nil
}

func denyProposal(gw, id, actor, token string) error {
	body, _ := json.Marshal(map[string]string{"decision": "deny", "actor": actor})
	url := strings.TrimSuffix(gw, "/") + "/v1/proposals/" + id + "/decision"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-Ledgerline-Token", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	return nil
}

// runContain freezes one session from the CLI.
func runContain(args []string) error {
	// Pull the session ID (first non-flag arg); flags may come in any order.
	valued := map[string]bool{"gateway": true, "actor": true, "token": true, "reason": true}
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
	fs := flag.NewFlagSet("contain", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	actor := fs.String("actor", defaultActor(), "who is containing the session")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	reason := fs.String("reason", "", "why the session is contained")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: ledgerline contain <session-id>")
	}
	body, _ := json.Marshal(map[string]string{"actor": *actor, "reason": *reason})
	url := strings.TrimSuffix(*gw, "/") + "/v1/sessions/" + url.PathEscape(id) + "/contain"
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
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	fmt.Printf("contained %s by %s\n", id, *actor)
	return nil
}

// runContained lists frozen sessions.
func runContained(args []string) error {
	fs := flag.NewFlagSet("contained", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(*gw, "/")+"/v1/contained", nil)
	if err != nil {
		return err
	}
	if *token != "" {
		req.Header.Set("X-Ledgerline-Token", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(body)))
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no contained sessions")
		return nil
	}
	for _, c := range list {
		fmt.Printf("%v  actor=%s  reason=%s  at=%v\n", c["session_id"], strOrDash(c["actor"]), strOrDash(c["reason"]), c["contained_at"])
	}
	return nil
}

// strOrDash prints a JSON value, or "-" when it is absent.
func strOrDash(v any) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return "-"
}

func fetchProposals(gw, token string) ([]map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(gw, "/")+"/v1/proposals", nil)
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

// runProposals lists actions proposed for out-of-band application.
func runProposals(args []string) error {
	fs := flag.NewFlagSet("proposals", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	list, err := fetchProposals(*gw, *token)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no pending proposals")
		return nil
	}
	for _, p := range list {
		argsStr := ""
		if a, ok := p["args"]; ok && a != nil {
			raw, _ := json.Marshal(a)
			s := string(raw)
			if len(s) > 90 {
				s = s[:90] + "..."
			}
			argsStr = "  args=" + s
		}
		fmt.Printf("%s  session=%v  tool=%v%s\n", p["id"], p["session_id"], p["tool"], argsStr)
	}
	return nil
}

// runApply records a proposal as applied out of band. The gateway
// never forwards a proposal; application is the human's own act,
// and this command only witnesses it.
func runApply(args []string) error {
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
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	actor := fs.String("actor", defaultActor(), "who applied the proposal out of band")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: ledgerline apply <proposal-id>")
	}
	body, _ := json.Marshal(map[string]string{"decision": "apply", "actor": *actor})
	url := strings.TrimSuffix(*gw, "/") + "/v1/proposals/" + id + "/decision"
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
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	fmt.Printf("applied %s by %s\n", id, *actor)
	return nil
}

// runIdempotency lists the durable executor's journal: one line
// per keyed execution, without replay bodies.
func runIdempotency(args []string) error {
	fs := flag.NewFlagSet("idempotency", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	state := fs.String("state", "", "filter by state (held, started, completed, denied, unknown, resolved, discarded)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	url := strings.TrimSuffix(*gw, "/") + "/v1/idempotency"
	if *state != "" {
		url += "?state=" + *state
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if *token != "" {
		req.Header.Set("X-Ledgerline-Token", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(body)))
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no idempotency records")
		return nil
	}
	for _, rec := range list {
		resolution := strOrDash(rec["resolution"])
		fmt.Printf("%v  session=%v  tool=%v  state=%v  resolution=%s\n", rec["key"], rec["session_id"], rec["tool"], rec["state"], resolution)
	}
	return nil
}

// runResolve reconciles one unknown outcome: the human records
// whether the call executed. A resolved-executed key never
// re-forwards; a resolved-not-executed key may run fresh.
func runResolve(args []string) error {
	valued := map[string]bool{"gateway": true, "actor": true, "token": true, "note": true}
	var positional []string
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
		positional = append(positional, a)
	}
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	actor := fs.String("actor", defaultActor(), "who resolved the outcome")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	note := fs.String("note", "", "note recorded with the resolution")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if len(positional) != 3 {
		return fmt.Errorf("usage: ledgerline resolve <session> <key> <executed|not-executed>")
	}
	session, key, resolution := positional[0], positional[1], positional[2]
	if resolution != "executed" && resolution != "not-executed" {
		return fmt.Errorf("resolution must be executed or not-executed")
	}
	body, _ := json.Marshal(map[string]string{"session": session, "key": key, "resolution": resolution, "note": *note, "actor": *actor})
	url := strings.TrimSuffix(*gw, "/") + "/v1/idempotency/resolve"
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
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	fmt.Printf("resolved %s/%s as %s\n", session, key, resolution)
	return nil
}

// runTools shows the tool baseline, the latest observed surface,
// and any drift between them.
func runTools(args []string) error {
	fs := flag.NewFlagSet("tools", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSuffix(*gw, "/")+"/v1/tools", nil)
	if err != nil {
		return err
	}
	if *token != "" {
		req.Header.Set("X-Ledgerline-Token", *token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(body)))
	}
	var status struct {
		Baseline map[string]any      `json:"baseline"`
		Latest   map[string]any      `json:"latest"`
		Drift    bool                `json:"drift"`
		Detail   map[string][]string `json:"drift_detail"`
		Pending  bool                `json:"pending_reapprove"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return err
	}
	names := func(v map[string]any) string {
		if v == nil {
			return "-"
		}
		tools, _ := v["tools"].([]any)
		var out []string
		for _, t := range tools {
			out = append(out, fmt.Sprint(t))
		}
		return strings.Join(out, ", ")
	}
	fmt.Printf("baseline: %s\nlatest:   %s\ndrift:    %v\n", names(status.Baseline), names(status.Latest), status.Drift)
	if status.Drift && status.Detail != nil {
		fmt.Printf("added:    %s\nremoved:  %s\nchanged:  %s\n",
			strings.Join(status.Detail["added"], ", "),
			strings.Join(status.Detail["removed"], ", "),
			strings.Join(status.Detail["changed"], ", "))
	}
	if status.Pending {
		fmt.Println("re-approval pending: the next observed list becomes the new baseline")
	}
	return nil
}

// runAcceptTools marks the next observed tool surface as the new
// baseline. It changes nothing by itself: the human accepts after
// reviewing the drift, and the next list is what gets trusted.
func runAcceptTools(args []string) error {
	fs := flag.NewFlagSet("accept-tools", flag.ExitOnError)
	gw := fs.String("gateway", "http://localhost:8080", "gateway address")
	actor := fs.String("actor", defaultActor(), "who accepted the new tool surface")
	token := fs.String("token", os.Getenv("LEDGERLINE_API_TOKEN"), "gateway API token (or env LEDGERLINE_API_TOKEN)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"actor": *actor})
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(*gw, "/")+"/v1/tools/accept", bytes.NewReader(body))
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
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gateway: %s", strings.TrimSpace(string(respBody)))
	}
	fmt.Println("re-approval pending: the next observed tool surface becomes the new baseline")
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
	if err := s.Wait(); err != nil {
		// Propagate the captured command's exit code: a caller
		// wrapping an agent in a script must see its failure.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCodeError{code: ee.ExitCode()}
		}
		return err
	}
	return nil
}

// exitCodeError asks main to exit with a specific code and no
// message (used for the captured command's own exit status).
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit code %d", e.code) }

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
