# Ledgerline: Vision and Architecture

Status: Phase 1 shipped 2026-10-20 (this repo). This document is the design record from 2026-10-19, revised after adversarial review, kept for the reasoning. Where the shipped code differs from the design below, the code and `SECURITY.md` win. Design only, not yet shipped: chain signing and external anchoring, redaction at capture, capture of call results and durations, the cost module, SIEM export, Postgres team mode, OIDC identity, published schemas, and a Docker image.
Date: 2026-10-19
Project name: Ledgerline (decided 2026-10-19)
License target: Apache 2.0
Builds on: Backseat (live PTY capture and approval forwarding for agent sessions)

## 1. Vision

Agents will run in production. Production needs trust.

Today, an agent can edit files, run shell commands, call APIs, and spend money. No open layer records what it did, who approved it, and what it cost. Teams either trust blind or block agents from real work.

This project builds that missing layer. Open source. For agents, not using agents. Any agent framework can plug into it. Any team can self host it.

The goal is simple: make agent work auditable, approvable, and accountable, the same way Linux made servers runnable, testable, and shared.

If this layer wins, it becomes the default trust substrate under agent deployments, in the same way OpenTelemetry became the default for observability.

## 2. Problem

Three questions have no standard answer today:

1. What did the agent do?
2. Who approved it?
3. What did it cost?

Current state:

- Agent logs live inside the agent framework. Each format is different. Logs are easy to edit or delete. Auditors cannot verify them.
- Approvals live in chat, in a UI popup, or nowhere. No record binds an approval to an identity, a time, and an exact action.
- Cost lives in a provider bill. The bill does not map to a session, a task, a user, or an approval.

Result:

- Security teams block agents from production systems.
- Platform teams build one off logging for each agent tool.
- Compliance teams have no evidence for SOC 2, ISO 27001, or EU AI Act Article 12 logging duties.
- Incidents take hours to reconstruct. No replay exists in open form.

The gap is not another agent. The gap is infrastructure around agents.

## 3. Principles

1. **For agents, not an agent.** This project does not reason, plan, or act. It records, checks, and proves.
2. **Boundary first.** Capture and enforcement sit at the boundary the agent must cross to act. The agent is never trusted to log itself.
3. **Framework neutral at the boundary.** Neutrality holds at the MCP boundary, where tool calls cross in a standard form. PTY capture covers terminal agents that do not use MCP. No claim of neutrality inside a framework process.
4. **Human approval is first class.** A high risk action does not proceed without a named human approval that is stored and verifiable. Approvals are enforced in path: the gateway blocks or allows the call.
5. **Tamper evident by default.** Records form a hash chain. Any edit breaks the chain and is visible.
6. **Local first, export ready.** Data stays with the operator by default. Export to SIEM and object storage is explicit.
7. **No lock in.** Plain formats. Open schemas. Export everything at any time.

## 4. Threat model

State the adversary plainly.

**Adversary.** A malicious agent that covers its tracks, or a compromised agent host that rewrites, deletes, or forges its own logs after the fact. A careless user who edits a log file is a weaker case of the same threat.

**Trust root.** The boundary gateway. The gateway runs separately from the agent host, under a different operator or at least a different trust domain. Tool calls cross the gateway to reach tools, files, and APIs. The gateway records what it sees and enforces what policy allows. The agent cannot record, edit, or delete the record of its own actions.

**Signing key (Phase 2 design, not shipped).** The Ed25519 chain head signing key will live with the gateway operator, not on the agent host. The operator holds it, rotates it on a set schedule and on any suspected compromise, and publishes the public key through a channel the reviewer trusts. A key on the agent host proves nothing. A key with the gateway operator does.

**What v1 proves, and what it does not.** A v1 replay bundle proves self consistency: the events form an unbroken hash chain. The chain is unsigned in v1, so this proves the record is internally consistent, not that the gateway wrote it, and anyone who can write the store can recompute the chain. External anchoring in Phase 2 adds authenticity: the chain head is published to an independent witness, so a later rewrite cannot match the anchored head.

**Out of scope.** A compromised gateway, or a gateway operator who colludes with the agent operator, breaks the model. That case needs separation of duties and external anchoring, and Phase 2 addresses it. v1 does not claim to survive it.

## 5. The three pillars

### Pillar 1: Session recording and audit

Question answered: What did the agent do?

- Capture at the boundary: every MCP tool call and its inputs, seen by the gateway. The shipped build records the call and its policy outcome, not the upstream result or its duration; outputs and timing are the design target.
- Capture at the terminal: PTY output, session start, and exit for terminal agents, from the Backseat capture path. Typed input is not recorded as an event in the shipped build.
- Store each event with a timestamp, session ID, agent ID, and parent event ID.
- Chain the event stream into a hash chain held by the gateway. Signing the chain is Phase 2 design.
- Support replay: step through a session second by second, on one timeline that merges boundary events and terminal events.

### Pillar 2: Approval chain ledger bound to identity

Question answered: Who approved it?

- Define policies by risk: read only actions pass, writes need approval, destructive or external actions need a second approver.
- Enforce in path. The gateway holds the tool call until a decision arrives, then allows or blocks it. Approval is not a note added after the fact.
- Route each approval request to a named human, in terminal, web, Slack, or mobile.
- Record the decision: who, when, what exact action, what context they saw, approve or deny.
- Bind identity with existing systems: OIDC, SSO, GitHub, and hardware keys where available. No new password store.
- Chain approvals to events. An action event must point to its approval event. An action with no approval is flagged in audit and in replay.

This pillar turns "someone clicked yes" into evidence an auditor can test.

### Pillar 3: Cost metering

Question answered: What did it cost?

- Meter token use, model calls, tool calls, and compute time per session, per task, per user, and per approval.
- Enforcement is native. This project is the boundary gateway, so a budget check runs in path: the gateway pauses or blocks a call when a session crosses its limit and asks for approval to continue. No separate gateway is needed for enforcement.
- Metering stays OpenTelemetry native. Export cost records in FOCUS format for finance teams to reconcile against provider invoices.
- Scope limit: this is a gateway for agent tool calls. It will not become a general LLM gateway. It does not compete with LiteLLM on provider routing, fallbacks, or model proxy features.

This pillar ships after Pillars 1 and 2 are stable. Trust comes first.

## 6. Architecture

```
Agent (any framework)
   |
   |  MCP tool calls
   v
[ Boundary Gateway ] ----> [ Policy Engine ] ----> [ Approval Ledger ]
   |        |                       |                        |
   |        v                       v                        v
   |   [ Tamper-Evident Store ]  [ Identity ]         [ Approval UI / API ]
   |
   |  Terminal I/O (co-capture)
   v
[ PTY Capture (Backseat) ] ---> [ Event Normalizer ] ---+
                                                          v
Tools / APIs / Files                            [ Replay Service ]
                                                          |
                                                          v
                                                   [ SIEM / Export ]
```

Both capture planes feed one event normalizer, one ledger, and one replay timeline. A reviewer sees one session, not two logs.

### 6.1 Capture plane: boundary first

**Primary plane: MCP boundary gateway.**

- The gateway sits between the agent and its MCP servers. Every tool call passes through it.
- Tool calls are seen as they cross: name and arguments. The shipped build does not record the upstream result, the duration, or a verified caller identity. Nothing depends on the agent reporting itself honestly.
- Approvals are enforced in path. Policy can allow, block, or hold a call for human approval before it reaches the tool.
- Framework neutrality is real here. Any agent that speaks MCP gets the same capture and enforcement, with no per framework shim.
- Cost budgets are enforced here too, in path, per session and per task.

**Co-capture plane: PTY capture, in the same Phase 1.**

- Backseat derived PTY capture records terminal agents: shell commands, terminal output, and interactive sessions that never touch MCP.
- This path is already built. It ships alongside the gateway, not after it.
- PTY events and gateway events share session IDs and merge into one timeline.

**Honest limit.** An action that crosses neither the MCP boundary nor a captured terminal is not recorded. Direct in process calls inside a framework, with no boundary crossing, stay out of scope. The docs must state what each plane covers.

### 6.2 Identity

- Each actor gets a stable ID: human user, agent instance, and service account.
- Humans auth via OIDC. Agents auth via a short lived token issued at session start, bound to the human or job that started it.
- Every event carries actor ID and session ID. No anonymous events.
- Support offline local mode with local keys for solo developers.
- Agent identity establishment is an open design question. See Section 14.

### 6.3 Approval ledger

- Append only log of approval requests and decisions, held by the gateway.
- Each entry includes: action hash, full action payload, requester ID, approver ID, decision, time, policy ID that triggered the request, and context shown to the approver.
- Policy engine is a simple rule file in v1 (YAML). Example rules: deny `rm -rf`, require approval for writes outside workspace, require approval for network egress, require two approvers for production deploys.
- Approval flow reuses Backseat forwarding: the expert sees the live session and the exact pending action before they decide.

### 6.4 Tamper-evident store

- Append only event store. SQLite for local mode (shipped), Postgres for team mode (Phase 2).
- Each event includes the hash of the prior event. Signing the chain head per session is Phase 2 design; the shipped chain is unsigned.
- The signing key will live with the gateway operator. See Section 4.
- Phase 2 anchor: publish the chain head hash to an external witness (git repo, object storage with retention lock, or a public timestamp service). v1 ships without anchoring and states that limit plainly.
- Schema is versioned JSON. OpenAPI and JSON Schema definitions are planned, not yet published.

### 6.5 Replay

- Web player that replays a session at real speed, 2x, or step by step.
- Timeline view links gateway events, terminal events, approvals, and cost on one line.
- Search across sessions by user, agent, command, file, or approval status.
- Export a replay bundle: a single file a reviewer can open offline to verify the hash chain and watch the session. v1 bundles prove self consistency. See Section 4.

### 6.6 SIEM and export

Design target, not shipped. The shipped export is the offline JSON bundle only.

- Stream events to Splunk, Elastic, Datadog, and generic webhooks via OpenTelemetry or syslog formats.
- Map events to common schemas so SOC tools need no custom parser.
- Retention controls: local retention days, cold export to S3 or GCS, and legal hold flag per session.

## 7. MVP wedge

Do not build the full platform first. Ship the narrow slice that proves trust.

**MVP: the open boundary gateway for agent tool calls, with terminal co-capture and replay.**

Scope:

1. MCP boundary gateway: capture all tool calls, enforce a policy file in path, hold risky calls for approval.
2. PTY co-capture from Backseat, merged into the same session timeline.
3. Durable recording with hash chain. Signing by a gateway key is Phase 2; the shipped chain is unsigned.
4. Approval ledger with identity: one approver named by CLI or web, with per-approver tokens binding the name to a credential. OIDC is later. Policy file with 5 to 10 starter rules.
5. Replay in the browser, on one timeline.
6. One export: JSON bundle. The SIEM webhook is Phase 2.

Target user for MVP: a platform or DevSecOps lead who runs coding agents on real repos and needs an audit trail for security review.

Success test for MVP:

- A reviewer with no access to the agent host can open a replay bundle, verify the hash chain, see each approval with a named approver, and confirm no gaps in the recorded boundary and terminal events. In v1 the bundle proves self consistency, not authorship; key based verification arrives with Phase 2 signing.
- Setup takes under 10 minutes on a laptop.
- Works with at least two agent tools on day one: one MCP based agent and one terminal agent (OpenCode).

Everything else waits until this wedge has real users and real feedback.

## 8. What it will not build

- It will not build an agent, a planner, or a model router.
- It will not become a general LLM gateway. It is a gateway for agent tool calls at the MCP boundary. Provider routing and model proxy features stay with LiteLLM and similar tools.
- It will not build a general SIEM or log analytics platform.
- It will not store secrets or act as a vault. The design records that a secret was used, not the secret value, with redaction rules at capture time. Redaction is not shipped yet: the current build stores arguments and terminal output as sent, so operators must treat the ledger as secret-bearing (see `SECURITY.md`).
- It will not add blockchain, tokens, or crypto incentives. A hash chain and signatures give the proof. No chain is needed.
- It will not require cloud hosting. Self host is the default. A hosted version, if it comes, is optional.

These limits keep the project focused and neutral. Neutral tools get adopted. Opinionated suites get forked or ignored.

## 9. Differentiation

No single feature in this design is unique. Session replay exists. Signed audit history exists. MCP gateways exist. The claim is narrower, and it is stated outright: **no open, self hosted system integrates boundary capture, an approval ledger enforced in path, terminal co-capture, replay, and auditor ready export on one substrate. The integrated open system is the product.**

Named competitors:

- **Mintive (commercial, closed source).** MCP gateway with agent monitoring, signed tamper evident access history with offline verification, and SIEM export. It covers about 70% of this vision and it ships today. The line: Mintive is closed and commercial. This project is open, self hosted, adds PTY co-capture and replay on the Backseat substrate, and binds approvals to actions enforced in path as open protocol, not as a vendor feature.
- **Ecliptica Replay (commercial).** Session replay and forensics for coding agents. It proves replay has demand. The line: replay alone is not a trust layer. This project ties replay to the gateway record, the approval ledger, and chain verification, in open form.

| Player type | What they do well | What they miss | This project |
|---|---|---|---|
| Mintive | MCP gateway, signed audit, SIEM export, shipping | Closed source, commercial, no PTY replay substrate | Open integrated system on Backseat substrate |
| Ecliptica Replay | Session replay for coding agents | Replay without gateway enforcement or approval ledger | Replay bound to capture, approvals, and chain |
| Agent frameworks | Run the agent | Logs are internal, editable, framework locked | Neutral record at the boundary, verifiable |
| Hash chain audit SDKs | Prove a log was not edited | No capture, no approvals, no replay, near zero adoption | Full stack from capture to replay |
| LLM gateways (LiteLLM, Portkey) | Budget and route model calls | No tool call session record, no approval chain | Tool boundary gateway with approval and session record |
| Session recorders (Teleport, asciinema) | Record human terminal work | Built for humans, not agents; no tool call semantics | Agent native events from gateway and terminal |
| Observability (Langfuse, Helicone) | Traces and evals for LLM apps | Quality and latency, not approval evidence | Compliance grade evidence with identity bound approvals |

Core edge: Backseat owns live terminal capture and live approval forwarding today, and the gateway design sits where agents must cross to act. Others would need to build both planes and the ledger that joins them.

Second edge: the builder runs this in real DevSecOps work. Policies and audit views come from real security reviews, not from theory.

## 10. Tech choices

- **Language: Go** for the gateway, capture proxy, store, and server. Single binary, low latency, strong fit with Backseat which is already in Go.
- **Boundary protocol: MCP first.** The gateway proxies MCP tool calls. Non MCP tools enter through PTY capture or not at all in v1.
- **Store: SQLite (local, shipped) and Postgres (team, Phase 2).** Append only tables plus hash chain columns.
- **Schemas: JSON with JSON Schema, plus OpenTelemetry semantic conventions** where they fit. Publishing the schemas in the repo is planned, not yet done.
- **Identity: OIDC first (design).** Support GitHub and Google as starter providers, plus generic OIDC. The shipped build uses named actors, with per-approver tokens binding a name to a credential.
- **Signing: Ed25519 (Phase 2 design)** for event chain heads and replay bundles. Key held by the gateway operator, with rotation. See Section 4.
- **Frontend: small web app for replay and approvals.** Server rendered where possible, minimal JS. Must work offline for bundle review.
- **Policy: YAML rule file in v1 (shipped).** Move to a proper policy language (Rego or Cedar) only after user feedback proves the need.
- **Packaging: single binary (shipped). Docker image planned.** Install with one command. No Kubernetes required for MVP.
- **Secrets handling: redaction at capture (design, not shipped).** A pattern list plus user rules will strip keys, tokens, and passwords before storage. Until then, arguments and output are stored as sent.

Open choices to test in MVP: gateway latency under high tool call volume, PTY proxy overhead on long sessions, and SQLite write limits under parallel agents.

## 11. Name candidates

Decided 2026-10-19: Ledgerline. The rest of this section is the historical record of that decision.

Removed after conflict checks: Trustline (XRP DeFi and an AI agent payments risk product), Warden (funded Cosmos L1 for AI agents, direct collision), Overwatch (Blizzard), and Attest (weak: the word is owned in practice by the Sigstore attestation ecosystem).

Survivors from the first list:

1. **Ledgerline** - Points to the approval ledger core. Descriptive and distinct. Longer than ideal. No dominant conflict found.
2. **Backseat Trust** - Reuse the Backseat brand and its users. Lowest launch cost. Risk: ties the trust layer too tight to one capture tool, and this project now leads with the gateway, not the terminal.

Fresh candidates, first pass only, formal check still needed:

3. **Gateledger** - Gateway plus ledger, the two core parts in one word. Risk: generic, and ledger names are crowded in fintech.
4. **Callsheet** - A record of every call, borrowed from film production. Short and distinct. Risk: does not signal security or trust on first hearing.
5. **Provenance** - What the system proves: where each action came from and who approved it. Risk: long, and used by data lineage tools.
6. **Turnstile** - A boundary that checks passage. Memorable. Risk: Cloudflare owns Turnstile as a product name in web security. Likely dead on check.
7. **Signpost** - A signed record that points to what happened. Risk: weak security signal, common word with many small products.

Pick criteria: one or two syllables if possible, no dominant conflict in dev tools or security, domain and GitHub org name open, easy to say in a meeting.

Next step is a formal conflict check on the top two picks before any rename, the same check run for FairMarket.

## 12. Roadmap

### Phase 0: Design and validation (Weeks 1 to 2)

- Publish this design doc in the new repo. Open Discussions.
- Talk to 5 platform or security leads who run agents today. Test the wedge: would gateway capture plus approval ledger plus replay pass their security review?
- Freeze MVP schemas: Event, Approval, Session, Identity. The multi agent data model (Section 14) must be settled before the freeze.

### Phase 1: MVP wedge (Weeks 3 to 8)

- MCP boundary gateway with capture, policy file, and in path approval.
- PTY co-capture to the same durable store with hash chain.
- Browser replay with one merged timeline.
- Replay bundle export and verify command.
- Docs, quick start, and a 90 second demo video. (Docs and quick start shipped; the demo video is not yet made.)
- Launch: Show HN, Backseat user note, and direct outreach to design partners.

### Phase 2: Team mode and anchoring (Months 3 to 4)

- External anchoring of chain heads to an independent witness. This adds authenticity to the v1 self consistency proof.
- Postgres store, multi user identity, role based access for approvers and reviewers.
- Two approver rule for high risk actions.
- SIEM export to Splunk and Elastic, plus generic webhook.
- Remote agent transport: gateway operation when the agent does not run on the gateway host.

### Phase 3: Cost module (Months 5 to 6)

- Token and tool cost metering per session, OpenTelemetry export.
- Budgets enforced in path at the gateway, with approval to resume.
- FOCUS export and invoice reconciliation view.

### Phase 4: Hardening and adoption (Month 7 on)

- External security review of the hash chain, signing, and gateway design.
- Compliance packs: sample evidence bundles mapped to SOC 2 and EU AI Act Article 12.
- Plugin API for custom capture sources and policy checks.
- Governance doc, RFC process, and contributor guide, on the FairMarket repo pattern.

Timelines are targets, not promises. Each phase ships only when the prior phase has real users.

## 13. Risks and mitigations

- **Risk: capture misses actions that cross no boundary.** In process framework calls bypass both planes. Mitigation: state coverage plainly per plane. Expand boundary coverage by demand, not by promise.
- **Risk: commercial competitors ship faster.** Mintive and Ecliptica Replay already ship parts of this vision. Mitigation: open source, self hosted, integrated system. Speed on the wedge, not on breadth.
- **Risk: users see audit as friction.** Mitigation: read only actions pass with no prompt. Only risky actions ask for approval. Keep approval under 5 seconds in the UI.
- **Risk: privacy and secret leakage in recordings.** Mitigation: redaction at capture (planned, not shipped), local first storage, and a clear data handling doc. Until redaction ships, the docs state plainly that the ledger is secret-bearing. The tension between full action payload and redaction stays open and visible.
- **Risk: framework vendors ship their own audit and close the gap.** Mitigation: stay neutral at the boundary. Vendor logs will stay vendor locked. Neutral, verifiable records are the wedge.

## 14. Open questions

Answered by the Phase 1 build: question 8 (YAML in v1) and question 10 (a new repo). The rest remain open.

1. Which MCP based agent tool is the design partner for the MVP, alongside OpenCode on the terminal plane? Pick by user demand from the Phase 0 talks.
2. **Multi agent data model.** One hash chain per session, or one chain per agent tree? How do subagent fan out, parallel branches, and handoffs map to sessions, and how do approval chains compose across a tree? This must be answered before the Phase 0 schema freeze.
3. **Remote agent transport.** What happens when the agent does not run on the gateway host? How do tool calls reach the gateway, how is that channel authenticated and encrypted, and what latency does it add? Backseat is remote by design; the trust layer cannot assume localhost.
4. **Agent identity establishment.** How is an agent identity created and verified: DIDs, SPIFFE, or provider issued credentials bound to OIDC? The approval ledger is only as strong as this answer.
5. Does the approval UX live in terminal, web, or chat first? Backseat points to web plus terminal. Confirm with design partners.
6. How much prompt content should the record store by default? Full prompt helps audit but raises privacy risk. A policy setting per team is likely. Needs a default call.
7. What witness should anchor the hash chain head in Phase 2? Git, object storage with retention lock, or a timestamp service. Cost and trust trade offs differ.
8. Should policies ship as YAML in v1 or start with Cedar or Rego? YAML is faster to ship. A policy language is stronger at scale.
9. What license for schemas vs code? Apache 2.0 for both is the current plan. Confirm before repo launch.
10. Host the project as a new repo or as a Backseat module first? A new repo signals the broader scope. A module reuses users faster. Decide in Phase 0.
11. Which SIEM format ships first in Phase 2? Follow design partner demand, not a guess.

## 15. Call to action

Read this doc. Mark what is wrong. The Phase 0 user talks decide if the wedge is right.

If the wedge holds, the next artifact is the MVP schema set and a one page quick start. No code for the full platform until the wedge is proven in the field.
