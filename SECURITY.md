# Security Policy

## Reporting a vulnerability

Email allanianirudh05@gmail.com with a description of the issue and steps to reproduce it. You will get a reply within 7 days. Do not open a public issue for a suspected vulnerability.

## Scope and honest limitations

Ledgerline is a trust boundary, so its own limits are stated plainly. The design threat model is in `docs/VISION.md` section 4. The current honest limitations:

- The hash chain is unsigned SHA-256. There is no signing key in the current build. Anyone who can write the ledger store can recompute the whole chain and produce a valid one. Tamper evidence holds against edits that do not recompute the chain, and for bundles checked against a chain head the reviewer obtained separately. Signing and external anchoring are Phase 2 design, not shipped.
- Offline bundles prove self-consistency (the chain is intact), not authenticity (who wrote it).
- The control plane is open by default. With no `--api-token` and no per-approver tokens, anyone who can reach the gateway port can read session events (tool arguments included), export bundles, and decide approvals. The gateway logs a warning at startup in that case. Set a token before exposing the port beyond loopback. The proxy path itself is never authenticated by design: anyone who can reach the port can send tool calls through to the upstream MCP server.
- Approvals exist and are enforced in path (CLI and web page). With a per-approver token, the recorded approver name is bound to the credential. With only a shared token, or none, the recorded name is the one the caller supplies: a claim, not a proof.
- There is no redaction at capture yet. Tool arguments and terminal output are stored exactly as sent. Treat the ledger file and every exported bundle as secret-bearing.
- Capture records each tool call and its policy outcome. It does not record the upstream result or the call duration yet.
- Containment freezes a session inside a running gateway: the triggering call is denied, every further call from the session is denied, and pending held calls from it are denied. It is not a kill switch that survives a gateway restart, and it does not stop an agent process running outside the gateway (for example, a PTY session started by `ledgerline run`). A contained session unfreezes if the gateway restarts.
- A proposal is never forwarded. The agent is told the action was NOT executed, and a human applying it out of band is the human's own act, outside the gateway's observation. The ledger records that a human claimed to apply it, not that the action happened.
- Upstream pinning covers the configured upstream URL only (SHA-256 of the normalized URL, stored in the pin file). It proves the configured upstream did not change since the pin was set; it does not verify what the upstream server is, and a re-approval is only as trustworthy as the operator who passed `--reapprove-upstream`.

If you find a gap between what the docs promise and what the code does, that is a security issue. Report it.
