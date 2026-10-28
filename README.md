# Ledgerline

The open trust substrate for AI agents. For agents, not using agents.

Agents will run in production. Production needs trust. Ledgerline answers three questions no open layer answers today:

1. **What did the agent do?** Every tool call crossing the boundary is witnessed into a hash-chained ledger (unsigned in v1; see the honest limits in `SECURITY.md`).
2. **Who approved it?** Policy is enforced in-path: allow, deny, or hold for human approval. The approval binds to the action in the ledger.
3. **What did it cost?** (Later module.) OTel-native metering with FOCUS export. It will not become another LLM gateway.

## How it works

Ledgerline is a boundary gateway. It sits between the agent (any MCP client) and the upstream MCP server. The agent is never trusted to log itself.

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
# --db makes the ledger survive restarts (SQLite); omit for in-memory.
# Policy comes from a YAML file (see policy.example.yaml) or from
# the quick --deny/--hold lists. This example binds loopback only.
./ledgerline gateway --upstream http://localhost:3001 --listen 127.0.0.1:8080 \
  --db ledger.db --policy policy.example.yaml

# Point your MCP client at http://localhost:8080
# Held calls wait for a human, in the browser or the terminal:
#   open http://localhost:8080/approvals in a browser
./ledgerline approvals --gateway http://localhost:8080 --watch
./ledgerline approve <id> --actor alice

# Three more policy actions exist. Contain freezes a session: the
# triggering call is denied, every further call from the session is
# denied, and its pending held calls are denied too. A human can
# also freeze a session from the control plane at any time:
#   ./ledgerline contain <session-id> --reason "suspicious holds"
#   ./ledgerline contained
# Propose records a call for out-of-band application and never
# forwards it: the agent is told the action was NOT executed, and a
# human applies it (or denies it) afterwards, outside the gateway:
#   ./ledgerline proposals
#   ./ledgerline apply <proposal-id>
#   ./ledgerline deny <proposal-id>

# Pin the upstream server so a changed upstream cannot slip in
# silently. The first run writes the pin; later runs refuse to start
# on a mismatch until a human re-approves (witnessed in the ledger):
#   ./ledgerline gateway ... --upstream-pin-file upstream.pin
#   ./ledgerline gateway ... --upstream-pin-file upstream.pin --reapprove-upstream

# The ledger stores tool arguments as sent. There is no redaction
# yet: treat ledger.db and exported bundles as secret-bearing.

# Guard the control plane before exposing the gateway beyond
# loopback. With no token, anyone who can reach the port can read
# the ledger (arguments included) and decide approvals. The proxy
# path itself is never authenticated by design: anyone who can
# reach the port can also send tool calls to your upstream server.
./ledgerline gateway ... --api-token "$LEDGERLINE_API_TOKEN"

# Bind approver names to credentials with per-approver tokens:
# a decision made with one is recorded in the ledger under the
# bound name, and the request cannot override it.
./ledgerline gateway ... --approver-token alice=TOKEN1 --approver-token bob=TOKEN2
# With only a shared --api-token (or none), the recorded approver
# name is the one the caller supplies: it is a claim, not a proof.

# Run a terminal session into the same ledger (shares --db):
./ledgerline run --db ledger.db --session demo -- opencode run "fix the bug"

# Watch the unified timeline (open this in a browser):
#   http://localhost:8080/replay?session=demo

# Export an offline bundle and verify it without host access:
./ledgerline export --db ledger.db --session demo --out demo.jsonl
./ledgerline verify demo.jsonl
```

## Layout

- `cmd/ledgerline` — CLI: `gateway`, `approvals`, `approve`, `deny`, `contain`, `contained`, `proposals`, `apply`, `export`, `verify`, `run`
- `internal/gateway` — the boundary proxy: intercepts `tools/call`, consults policy, holds for approval, contains sessions, records proposals, forwards the rest; serves the `/v1/*` API, the `/approvals` page, and `/replay`
- `internal/ledger` — `Store` interface; in-memory chain and SQLite backend; chain verification
- `internal/policy` — allow/deny/hold/contain/propose decisions from a YAML policy file (ordered rules, glob tool names, decoded-JSON argument matching that fails closed, configurable default) or static lists (entries are tool globs)
- `internal/pty` — PTY co-capture: runs a command, witnesses terminal output into the same ledger
- `internal/replay` — offline bundle export (prefix-closed, so the chain verifies) and the timeline viewer
- `docs/VISION.md` — the full vision and architecture doc

## Status

Phase 1 wedge complete. See `docs/VISION.md` for the design, the threat model, and what this project will not build.

Honest limits of the current build (also in `SECURITY.md`):

- The hash chain is unsigned. Bundles prove self-consistency, not who wrote them. Signing and external anchoring are Phase 2.
- No redaction at capture yet. Arguments and terminal output are stored as sent.
- The gateway sets no timeout on upstream calls, so long-lived streaming sessions are never cut off, and a hung upstream holds a request open.
- Capture records the call and its policy outcome, not the upstream result or its duration.
- Containment is a session freeze inside a running gateway, not a kill switch that survives a gateway restart. A contained session unfreezes if the gateway restarts.
- Upstream pinning covers the configured upstream URL only. It does not verify what the upstream server is, and it does not cover MCP servers reached any other way.

## Dogfood note

The gateway is tested end to end against the official MCP
"everything" reference server (`@modelcontextprotocol/server-everything`,
streamable HTTP): initialize, tools/list, an allowed call, a YAML-denied
call, and a held call approved from the CLI all pass, and the exported
bundle verifies. That run found two real bugs, both fixed: client
hop-by-hop headers (`Connection: close`) were forwarded upstream and
made strict servers answer 400, and argument whitespace differences
between clients broke bundle verification (hashes now use a compacted
form of the arguments). An adversarial review of the result (2026-10-20)
found and fixed a further set: argument conditions now evaluate the
decoded JSON and fail closed, path globs support `**` for any depth,
the approval release path checks its ledger writes, and approver
names can be bound to per-approver tokens.

## License

Apache 2.0. See `LICENSE`.
