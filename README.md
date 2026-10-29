# Ledgerline

The open trust layer for AI agents. It is built for agents. It is not built with agents.

Agents will run in production. Production needs trust. Ledgerline answers three questions. No other open layer answers them today:

1. **What did the agent do?** Every tool call that crosses the boundary goes into a hash-chained ledger. The chain is unsigned in v1. See the honest limits in `SECURITY.md`.
2. **Who approved it?** Policy runs in the request path. It allows, denies, or holds a call for human approval. The ledger binds the approval to the action.
3. **What did it cost?** This is a later module. It meters use with OTel and FOCUS export. It will not become another LLM gateway.

## How it works

Ledgerline is a boundary gateway. It sits between the agent (any MCP client) and the upstream MCP server. Ledgerline does not trust the agent to log itself.

```
Agent --(MCP/JSON-RPC)--> [ Ledgerline ] --(forward)--> MCP server
                              |
                     policy allow/deny/hold
                              |
                     hash-chained ledger
                              |
                     replay bundle + offline verify
```

## Quickstart

Requires Go 1.24 or newer.

```sh
go build -o ledgerline ./cmd/ledgerline

# Start an MCP server first if you do not have one. Any
# streamable-HTTP MCP server works. The official reference server:
#   npx @modelcontextprotocol/server-everything streamableHttp
# serves on http://localhost:3001.

# Proxy your MCP server. Deny dangerous tools, hold sensitive ones.
# --db keeps the ledger across restarts. It uses SQLite.
# Omit it for in-memory use.
# Policy comes from a YAML file (see policy.example.yaml) or from
# the quick --deny/--hold lists. This example binds loopback only.
./ledgerline gateway --upstream http://localhost:3001 --listen 127.0.0.1:8080 \
  --db ledger.db --policy policy.example.yaml

# Point your MCP client at http://localhost:8080
# Held calls wait for a human, in the browser or the terminal:
#   open http://localhost:8080/approvals in a browser
./ledgerline approvals --gateway http://localhost:8080 --watch
./ledgerline approve <id> --actor alice

# Three more policy actions exist. Contain freezes a session.
# It denies the triggering call. It denies new calls from the
# session. It cuts off in-flight requests for the session at the
# gateway. It also denies the pending held calls.
# Containment uses the session header. It also uses every
# upstream MCP session id seen on that session. Rotating the
# session header alone does not evade it. The agent must also
# abandon its upstream MCP session. This raises the cost of
# evasion. It does not remove it. The proxy path has no
# authentication by design. A fresh MCP session is a new
# identity. Full binding needs proxy-path client auth. A human
# can also freeze a session from the control plane at any time:
#   ./ledgerline contain <session-id> --reason "suspicious holds"
#   ./ledgerline contained
# Note: clients that send no session header share the "default"
# session. Containing "default" blocks every headerless client.
# Propose records a call for out-of-band application. It never
# forwards the call. The agent learns the action was NOT
# executed. A human applies it or denies it afterwards, outside
# the gateway.
# Identical retries return the existing proposal id instead of
# queueing duplicates. The queue holds 1000 proposals and entries
# expire after 24 hours. An "apply" record is only as trustworthy
# as the control-plane token. With no token set, anyone who can
# reach the port can mark a proposal applied. Treat no-token
# local use as single-user only:
#   ./ledgerline proposals
#   ./ledgerline apply <proposal-id>
#   ./ledgerline deny <proposal-id>

# Pin the upstream server. A changed upstream then cannot slip
# in silently. The first run writes the pin. Later runs refuse
# to start on a mismatch. A human must re-approve. The
# re-approval goes into the ledger:
#   ./ledgerline gateway ... --upstream-pin-file upstream.pin
#   ./ledgerline gateway ... --upstream-pin-file upstream.pin --reapprove-upstream

# Broker upstream credentials. The agent never holds them. The
# gateway injects them on every forwarded request. It denies
# foreign values under brokered header names. It denies tool
# calls whose arguments carry a brokered secret. It denies them
# before witnessing, so the secret never reaches the ledger. It
# redacts brokered values from upstream responses. Values come
# from the environment only. They never come from the config
# file (see broker.example.yaml):
#   UPSTREAM_API_KEY=... ./ledgerline gateway ... --broker broker.example.yaml
# Broker status (names and headers only, never values):
#   curl http://localhost:8080/v1/broker

# The ledger stores tool arguments as sent, except brokered
# secrets. Brokered secrets are denied before witnessing. They
# are redacted from responses. They never reach the ledger.
# Anything else the agent puts in arguments stays as sent. All
# PTY output stays as sent. Treat ledger.db and exported bundles
# as secret-bearing.

# Durable execution: a client that sends
# X-Ledgerline-Idempotency-Key on a tool call gets exactly-once
# semantics per key in its session. The gateway journals the
# call as started before forwarding. It replays the recorded
# response on retry (up to 1 MiB). It answers a concurrent retry
# as in-flight. It answers a retry of a held call with the same
# approval id instead of queueing a second hold. A key binds to
# one tool and one arguments hash. Reuse with a different tool
# or different arguments is denied. After a crash, started calls
# come back as unknown. Only a human resolution moves them.
# Executed keys never re-forward:
#   curl ... -H 'X-Ledgerline-Idempotency-Key: deploy-001' ...
#   ./ledgerline idempotency --state unknown
#   ./ledgerline resolve <session> <key> <executed|not-executed>
# Unkeyed calls behave exactly as before. Policy denials leave
# no record. A later retry re-evaluates current policy. Restart
# recovery needs a SQLite ledger (--db). In-memory mode keeps
# the journal only while the process lives.

# Tools-drift detection: the gateway records the upstream tool
# surface as a baseline. It takes the baseline from the startup
# probe. If the probe finds nothing, it takes the first
# tools/list that passes through. It enforces the baseline from
# then on. A tools/call for a name outside the baseline is
# denied until a human accepts the new surface. The baseline
# survives restarts in the ledger store. A restart does not
# grant the upstream amnesty. Removals and description/schema
# changes go into the ledger as drift. They do not block calls
# to baseline tools. Review and accept:
#   ./ledgerline tools
#   ./ledgerline accept-tools
# The next observed list then becomes the new baseline, witnessed
# in the ledger. Or accept at startup:
#   ./ledgerline gateway ... --reapprove-tools
# With no baseline at all, calls stay allowed. This happens when
# the upstream never answered tools/list. There is nothing to
# drift from yet. When the upstream is not up at startup, the
# gateway retries the probe quietly every 10s until a baseline
# exists.
# A paginated tools/list is never treated as a surface. This
# means a list with nextCursor present. The probe follows
# cursors to build the full baseline. A partial page that passes
# through is ignored. Page-2 tools are never denied as drift.
# Drift enforcement needs a control-plane token to mean what it
# says. With no --api-token or --approver-token, anyone who can
# reach the port can accept a new surface. This includes the
# agent itself. The gateway logs a warning at startup in that
# case.

# Hook bridge: check native tool calls, not just MCP calls.
# Native tools (Bash, file edits) never cross the MCP boundary.
# A harness calls the bridge before each native tool runs.
# The bridge uses the same policy engine as the gateway.
# It records each call in the ledger.
# Exit 0 allows the call. Exit 2 blocks it, and the reason goes
# to stderr, where the harness shows it to the agent.
# The bridge never exits 1: Claude Code and Gemini CLI treat
# any exit other than 0 or 2 as a non-blocking error.
# An allow means Ledgerline does not object. It does not grant
# harness permission: the harness still runs its own flow.
# With a gateway, a hold waits for a human decision, in the
# same queue as MCP holds. Without a gateway, a hold blocks
# with a note on how to approve and retry.
# If the bridge stops waiting, the gateway hold is cancelled.
# A late approval after that records no allow. The agent must
# retry for a fresh hold.
# A tiny race remains. If the gateway records an allow and the
# bridge disconnects before the answer lands, the ledger holds
# an allow for a call the harness may block. No acknowledgment
# protocol closes that window.
# The bridge waits the hold timeout plus 30 seconds of client
# grace. Set the harness hook timeout above that total.
# Claude Code counts timeouts in seconds. Set it above 150
# seconds for the 120 second default, and set onFailure to
# block, so a killed bridge blocks instead of waving the call
# through. Gemini CLI counts timeouts in milliseconds. Its
# default is 60 seconds. The bridge default for Gemini is 25
# seconds. The default wait is 55 seconds, so the bridge
# answers before Gemini kills it. Set the snippet timeout to
# 90000 milliseconds. When you raise the bridge timeout to T
# seconds, set the Gemini timeout above T plus 30 seconds, in
# milliseconds. Gemini has no fail-closed timeout option.
# A killed Gemini bridge lets the call through. Keep the bridge
# timeout below the Gemini timeout.
# Tool names map to one canonical set, so one policy file works
# across harnesses. Known Claude Code names map to lowercase.
# Other Claude Code names pass through unchanged. Gemini
# names map like this: run_shell_command to bash, read_file and
# read_many_files to read, write_file to write, replace to
# edit, grep_search to grep, search_file_content to search,
# web_fetch to webfetch, web_search to websearch,
# list_directory to list. Other names pass through unchanged.
# A policy that denies grep must also deny search to cover
# both Gemini search tools. The ledger cannot tell read_file
# from read_many_files. Both map to read.
# OpenCode plugins must build the bridge envelope themselves:
# tool, args, and session. Native OpenCode events carry input
# and output and block by throwing. The plugin maps those to
# the envelope and sends the session id. A missing session
# becomes the default session.
# No policy flags means allow-all: the bridge only records.
# An empty policy file is refused instead. Pass a policy file
# or a deny list or a hold list to enforce anything.
# The bridge ignores cwd. Policy authors must match absolute
# paths. Relative paths match as sent.
# Fail-open flips bridge errors to allows. That includes a
# gateway ledger outage: the gateway answers 503, the bridge
# allows, and no record exists for that allow. Policy denials
# still block under fail-open.
# With --broker, the standalone bridge scans arguments for
# brokered secrets and denies them before witnessing, like the
# gateway. Without --broker, it records arguments as sent,
# secrets included. Broker users who need the guarantee must
# pass --broker or use gateway mode.
#   # Claude Code (settings.json, PreToolUse, matcher "*"):
#   #   "command": "ledgerline hook --harness claude-code --db ledger.db --policy policy.yaml"
#   #   with: "timeout": 180, "onFailure": "block"
#   # Gemini CLI (settings.json, BeforeTool, matcher "*"):
#   #   "command": "ledgerline hook --harness gemini --db ledger.db --policy policy.yaml"
#   #   with: "timeout": 90000
#   # With a gateway (holds wait for approval):
#   #   ledgerline hook --harness claude-code --gateway http://localhost:8080 --token "$LEDGERLINE_API_TOKEN"
# Drift detection does not apply to hook calls: it guards the
# upstream MCP tool surface, not native harness tools.

# Guard the control plane before you expose the gateway beyond
# loopback. With no token, anyone who can reach the port can
# read the ledger. This includes arguments. Such a person can
# also decide approvals. The proxy path itself has no
# authentication by design. Anyone who can reach the port can
# also send tool calls to your upstream server.
./ledgerline gateway ... --api-token "$LEDGERLINE_API_TOKEN"

# Bind approver names to credentials with per-approver tokens.
# A decision made with one goes into the ledger under the bound
# name. The request cannot override it.
./ledgerline gateway ... --approver-token alice=TOKEN1 --approver-token bob=TOKEN2
# With only a shared --api-token, or none, the recorded approver
# name is the one the caller supplies. It is a claim, not a proof.

# Run a terminal session into the same ledger (shares --db):
./ledgerline run --db ledger.db --session demo -- opencode run "fix the bug"

# Watch the unified timeline (open this in a browser):
#   http://localhost:8080/replay?session=demo

# Export an offline bundle and verify it without host access:
./ledgerline export --db ledger.db --session demo --out demo.jsonl
./ledgerline verify demo.jsonl
```

## Layout

- `cmd/ledgerline` holds the CLI: `gateway`, `approvals`, `approve`, `deny`, `contain`, `contained`, `proposals`, `apply`, `idempotency`, `resolve`, `tools`, `accept-tools`, `export`, `verify`, `run`, `hook`
- `internal/gateway` is the boundary proxy. It intercepts `tools/call`. It consults policy. It holds calls for approval. It contains sessions. It records proposals. It brokers upstream credentials. It forwards the rest. It serves the `/v1/*` API, the `/approvals` page, and `/replay`
- `internal/ledger` holds the `Store` interface, the in-memory chain, the SQLite backend, and chain verification
- `internal/policy` makes allow/deny/hold/contain/propose decisions from a YAML policy file or static lists. The YAML file uses ordered rules, glob tool names, and decoded-JSON argument matching that fails closed. It has a configurable default. Static list entries are tool globs
- `internal/pty` is PTY co-capture. It runs a command. It witnesses terminal output into the same ledger
- `internal/replay` is offline bundle export and the timeline viewer. Bundles are prefix-closed, so the chain verifies
- `docs/VISION.md` is the full vision and architecture doc

## Status

Phase 1 wedge complete. See `docs/VISION.md` for the design, the threat model, and what this project will not build.

Honest limits of the current build (also in `SECURITY.md`):

- The hash chain is unsigned. Bundles prove self-consistency, not who wrote them. Signing and external anchoring are Phase 2.
- Redaction covers brokered secrets only. A tool call that carries a brokered secret is denied before witnessing. Brokered values are redacted from upstream responses. Any other secret in arguments stays as sent. All PTY output stays as sent. The ledger and bundles stay secret-bearing. The broker cannot revoke knowledge the agent already has from elsewhere. It does not scan non-tool traffic arguments.
- The gateway sets no timeout on upstream calls. Long-lived streaming sessions are never cut off. A hung upstream holds a request open.
- Capture records the call and its policy outcome. It does not record the upstream result or the call duration. Keyed calls are the exception. Their redacted responses go into the journal up to 1 MiB for replay. Larger responses complete without a replay copy.
- Containment is a session freeze inside a running gateway. It is not a kill switch that survives a gateway restart. A contained session unfreezes if the gateway restarts. Cancelling an in-flight request stops the gateway waiting. It cuts the response, so nothing from it reaches the agent. Whether the upstream itself stops depends on it observing cancellation. A started stream does stop. A plain request still awaiting its first byte may run to completion server-side, with its result discarded. Cancelling never undoes a side effect the upstream already executed.
- Containment binds the ledger session header. It also binds the upstream MCP sessions observed on it. Rotating the ledger header alone does not evade it. Starting a fresh upstream MCP session does evade it. Without proxy-path client authentication, a new MCP session is a new identity.
- Upstream pinning covers the configured upstream URL only. It does not verify what the upstream server is. It does not cover MCP servers reached any other way. The pin proves the configured upstream string matches the pin file, nothing more. The pin file itself has no protection against a same-user process. The first run trusts whatever upstream was passed.
- Proposal "apply" records claim a human applied the action out of band. With no control-plane token, anyone who can reach the port can create that record. Treat no-token local use as single-user only.
- Idempotency is per key, per session, for 24 hours, up to 1000 journal records. A replay bypasses current policy by design. The same key means the same call. A replay never bypasses containment. A resolved-executed key never re-forwards, even if the resolution was wrong. The human owns that call, not the gateway. Journal rows are durable, not hash-chained. Only the unknown and resolved transitions go into the chain.
- Tools-drift enforcement denies unknown tool names only. It acts only once a baseline exists. The first sighting is trusted (TOFU). A server already compromised before the first gateway start baselines its malicious tools. A tools/list response the gateway cannot parse changes nothing. In-memory mode loses the baseline on restart. The stored baseline row is not covered by chain verification. A process that can write the ledger DB can rewrite it while verify stays green. This is the same conceded DB-write power as the chain itself. Session bundles exclude gateway-wide baseline and drift events. The full chain holds them.

## Dogfood note

The gateway is tested end to end against the official MCP "everything" reference server. The server is `@modelcontextprotocol/server-everything`, streamable HTTP. The tests cover initialize, tools/list, an allowed call, a YAML-denied call, and a held call approved from the CLI. All pass. The exported bundle verifies.

That run found two real bugs. Both are fixed. Client hop-by-hop headers (`Connection: close`) were forwarded upstream. Strict servers then answered 400. Argument whitespace differences between clients broke bundle verification. Hashes now use a compacted form of the arguments.

An adversarial review of the result (2026-10-20) found and fixed a further set. Argument conditions now evaluate the decoded JSON and fail closed. Path globs support `**` for any depth. The approval release path checks its ledger writes. Approver names can be bound to per-approver tokens.

## License

Apache 2.0. See `LICENSE`.
