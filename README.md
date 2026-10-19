# Ledgerline

The open trust substrate for AI agents. For agents, not using agents.

Agents will run in production. Production needs trust. Ledgerline answers three questions no open layer answers today:

1. **What did the agent do?** Every tool call crossing the boundary is witnessed into a tamper-evident, hash-chained ledger.
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
                     replay bundle + SIEM export
```

## Quickstart

```sh
go build ./...

# Proxy your MCP server. Deny dangerous tools, hold sensitive ones.
# --db makes the ledger survive restarts (SQLite); omit for in-memory.
./ledgerline gateway --upstream http://localhost:3000 --listen :8080 \
  --db ledger.db --deny "exec,rm" --hold "write_file"

# Point your MCP client at http://localhost:8080
# Held calls wait for a human:
./ledgerline approvals --gateway http://localhost:8080
./ledgerline approve <id> --actor buppy

# Run a terminal session into the same ledger (shares --db):
./ledgerline run --db ledger.db --session demo -- opencode run "fix the bug"

# Watch the unified timeline:
open http://localhost:8080/replay?session=demo

# Export an offline bundle and verify it without host access:
./ledgerline export --db ledger.db --session demo --out demo.jsonl
./ledgerline verify demo.jsonl
```

## Layout

- `cmd/ledgerline` — CLI: `gateway`, `approvals`, `approve`, `deny`, `export`, `verify`, `run`
- `internal/gateway` — the boundary proxy: intercepts `tools/call`, consults policy, holds for approval, forwards the rest; serves `/v1/*` API and `/replay`
- `internal/ledger` — `Store` interface; in-memory chain and SQLite backend; chain verification
- `internal/policy` — allow/deny/hold decisions (static lists in v0, YAML policy next)
- `internal/pty` — PTY co-capture: runs a command, witnesses terminal output into the same ledger
- `internal/replay` — offline bundle export (prefix-closed, so the chain verifies) and the timeline viewer
- `docs/VISION.md` — the full vision and architecture doc

## Status

Scaffold, Phase 1 in progress. See `docs/VISION.md` for the design, the threat model, and what this project will not build.

## License

Apache 2.0. See `LICENSE`.
