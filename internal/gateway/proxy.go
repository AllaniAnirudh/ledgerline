// Package gateway is the boundary: an HTTP proxy that sits between an
// MCP client (the agent) and the upstream MCP server.
//
// Every JSON-RPC tool call crossing the boundary goes into the
// ledger. It is checked against policy before it is allowed
// through. Non-tool traffic is forwarded untouched.
//
// The gateway does not trust the agent to log itself. The gateway
// is the trust root for everything it witnesses. If the ledger
// cannot be written, the boundary fails closed: no witness, no
// passage.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// maxBodyBytes caps one proxied request body. Tool calls are
// small. The cap exists so a client cannot make the boundary
// buffer an unbounded request into memory.
const maxBodyBytes = 10 << 20

// maxControlBodyBytes caps one control-plane JSON body. Control
// bodies are small: a decision, a flip, a revocation. The cap
// exists so a client cannot make a handler buffer an unbounded
// body into memory.
const maxControlBodyBytes = 1 << 20

// maxListBytes caps one captured tools/list response. Tool lists
// are rarely near 1 MiB. Each in-flight list pins its capture
// buffer. The list cap is deliberately far below the request
// cap. An agent-triggered upstream cannot amplify memory 10 MiB
// per concurrent list.
const maxListBytes = 1 << 20

// Proxy forwards MCP traffic while witnessing and policing tool calls.
type Proxy struct {
	upstream    *url.URL
	ledger      ledger.Store
	policy      *policy.Policy
	client      *http.Client
	probeClient *http.Client // baseline probe only: a hung upstream must not hang startup
	approvals   *Approvals
	proposals   *Proposals
	broker      *Broker
	apiToken    string
	approvers   map[string]string // token -> approver name

	containedMu   sync.Mutex
	contained     map[string]containedSession
	containedMCP  map[string]bool            // upstream MCP session ids frozen with their sessions
	observed      map[string]map[string]bool // ledger session -> MCP session ids seen on it
	upstreamPin   string
	pinConfigured bool
	policyHash    string // SHA-256 hex of the policy file, captured at startup

	// Peer gateways for the dashboard pull. Set at startup
	// from the peers file. The list never changes while the
	// gateway runs. peersMu guards reads against SetPeers.
	peersMu    sync.RWMutex
	peers      []PeerConfig
	peerClient *http.Client // one client, 5 second timeout per peer

	// Mode flip state. policyMu guards the policy pointer,
	// the policy hash, the overrides map, and the file
	// paths. Readers take the read lock. A flip takes the
	// write lock. The policy value itself is never mutated
	// in place. A flip swaps in a fresh parsed policy.
	policyMu        sync.RWMutex
	policyFileBytes []byte // nil when the policy came from static lists
	policyFilePath  string
	policyModesPath string
	policyModes     policy.ModeOverrides

	// Agent token auth (opt-in). When requireAgentToken is set,
	// every proxy-path request must carry a valid token. The
	// key signs and checks tokens. Revoked token ids live in
	// memory and in the revocation file. See token.go.
	requireAgentToken     bool
	tokenKey              []byte
	tokenAudienceOverride string
	tokenStrictAudience   bool
	revokedMu             sync.Mutex
	revoked               map[string]bool
	revokeFile            string

	inflightMu sync.Mutex
	inflight   map[string]map[*inflightReq]struct{}

	idemMu sync.Mutex // guards the purge-count-claim sequence

	toolsMu               sync.Mutex
	toolsBaseline         *ledger.ToolsBaseline // trust anchor, nil until established
	toolsLatest           *ledger.ToolsBaseline // most recently observed surface
	toolsReapprovePending bool
	toolsReapproveActor   string
}

// inflightReq is one cancellable upstream request. It is keyed by
// pointer. A CancelFunc itself is not a map key.
type inflightReq struct {
	cancel context.CancelFunc
}

// SetAPIToken guards the /v1 control plane. When a token is set,
// every /v1 request must carry it as "Authorization: Bearer <token>"
// or the X-Ledgerline-Token header. Empty means no check. Use
// empty only for local use. The control plane can approve held
// calls, so guard it before exposing the gateway beyond
// localhost.
func (px *Proxy) SetAPIToken(t string) { px.apiToken = t }

// SetApproverToken binds one token to one approver name. A
// decision made with an approver token goes into the ledger under
// the bound name. The request body cannot override it. Approver
// tokens also pass the control-plane token check.
func (px *Proxy) SetApproverToken(name, token string) {
	if px.approvers == nil {
		px.approvers = map[string]string{}
	}
	px.approvers[token] = name
}

func requestToken(r *http.Request) string {
	if t := r.Header.Get("X-Ledgerline-Token"); t != "" {
		return t
	}
	if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
		return strings.TrimPrefix(a, "Bearer ")
	}
	return ""
}

// tokenEqual compares two tokens in constant time. It compares
// digests, so length does not leak either.
func tokenEqual(got, want string) bool {
	g := sha256.Sum256([]byte(got))
	w := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(g[:], w[:]) == 1
}

func (px *Proxy) tokenOK(r *http.Request) bool {
	if px.apiToken == "" && len(px.approvers) == 0 {
		return true
	}
	got := requestToken(r)
	if got == "" {
		return false
	}
	if px.apiToken != "" && tokenEqual(got, px.apiToken) {
		return true
	}
	for token := range px.approvers {
		if tokenEqual(got, token) {
			return true
		}
	}
	return false
}

// approverActor returns the name bound to the request's token.
// It applies when the request authenticated with a per-approver
// token.
func (px *Proxy) approverActor(r *http.Request) (string, bool) {
	got := requestToken(r)
	if got == "" {
		return "", false
	}
	for token, name := range px.approvers {
		if tokenEqual(got, token) {
			return name, true
		}
	}
	return "", false
}

// New builds a proxy for one upstream MCP server base URL.
func New(upstream string, l ledger.Store, p *policy.Policy) (*Proxy, error) {
	u, err := url.Parse(strings.TrimSuffix(upstream, "/"))
	if err != nil {
		return nil, err
	}
	px := &Proxy{upstream: u, ledger: l, policy: p, client: &http.Client{}, probeClient: &http.Client{Timeout: 30 * time.Second}, peerClient: &http.Client{Timeout: peerTimeout}, approvals: NewApprovals(), proposals: NewProposals(), policyHash: p.Hash(), policyModes: policy.ModeOverrides{}}
	if err := px.recoverIdempotency(); err != nil {
		return nil, err
	}
	if err := px.loadToolsBaseline(); err != nil {
		return nil, err
	}
	return px, nil
}

// Approvals exposes the pending human-approval queue.
func (px *Proxy) Approvals() *Approvals { return px.approvals }

// Proposals exposes the pending out-of-band proposal queue.
func (px *Proxy) Proposals() *Proposals { return px.proposals }

// SetBroker installs the credential broker. Nil means no broker.
// Upstream credentials pass through untouched, as before.
func (px *Proxy) SetBroker(b *Broker) { px.broker = b }

// SetUpstreamPin records the pinned upstream identity for the
// /v1/upstream endpoint. Empty means pinning is not configured.
func (px *Proxy) SetUpstreamPin(pin string) {
	if pin == "" {
		return
	}
	px.upstreamPin = pin
	px.pinConfigured = true
}

// SetPeers installs the peer gateway list for the dashboard
// pull. Call it at startup, before serving.
func (px *Proxy) SetPeers(peers []PeerConfig) {
	px.peersMu.Lock()
	defer px.peersMu.Unlock()
	px.peers = peers
}

// policyNow returns the current policy. The flip swaps the
// pointer under the write lock. A call in flight keeps the old
// policy. The old value is immutable, so that is safe.
func (px *Proxy) policyNow() *policy.Policy {
	px.policyMu.RLock()
	defer px.policyMu.RUnlock()
	return px.policy
}

// policyHashNow returns the current effective policy hash.
func (px *Proxy) policyHashNow() string {
	px.policyMu.RLock()
	defer px.policyMu.RUnlock()
	return px.policyHash
}

// SetPolicySource records where the policy came from. A flip
// needs the file bytes to re-parse and the modes path to
// persist. A static policy has no bytes and no path. Flips
// then refuse with a 400.
func (px *Proxy) SetPolicySource(filePath string, fileBytes []byte, modesPath string, modes policy.ModeOverrides) {
	px.policyMu.Lock()
	defer px.policyMu.Unlock()
	px.policyFilePath = filePath
	px.policyFileBytes = fileBytes
	px.policyModesPath = modesPath
	if modes == nil {
		modes = policy.ModeOverrides{}
	}
	px.policyModes = modes
}

// Ledger exposes the underlying store for export and the replay API.
func (px *Proxy) Ledger() ledger.Store { return px.ledger }

// jsonRPC is the minimal shape we need to spot a tool call.
type jsonRPC struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
	ID     json.RawMessage `json:"id"`
}

type toolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (px *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Approval and replay API live on the same port, outside the proxy path.
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/replay" || r.URL.Path == "/approvals" || r.URL.Path == "/dashboard" {
		px.serveAPI(w, r)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	r.Body.Close()
	if len(body) > maxBodyBytes {
		http.Error(w, "ledgerline: request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	session, err := sessionOf(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mcpID := r.Header.Get("Mcp-Session-Id")
	px.observeMCP(session, mcpID)

	// Agent token check. It runs before containment, policy,
	// and forwarding. A rejected request is not witnessed. It
	// has no agent id to attribute. The rejection goes to
	// stderr only. The control plane above never needs it.
	agentID := ""
	if px.requireAgentToken {
		claims, err := px.validateAgentToken(r)
		if err != nil {
			px.rejectAgentAuth(w, body, err)
			return
		}
		agentID = claims.AgentID
		r = withAgentID(r, agentID)
	}

	// A contained session is cut off entirely. No tool call,
	// no list, and no other proxied traffic passes. The
	// control plane above is unaffected. A human can still
	// inspect the session. It stays contained until a new
	// gateway start. Containment holds only while this
	// gateway process lives. It is a session freeze, not a
	// kill switch that survives a gateway restart. It is
	// keyed on the ledger session AND on every upstream MCP
	// session id observed on it. Rotating the ledger header
	// alone does not evade it. The agent must also abandon
	// its upstream MCP session. That raises the cost of
	// evasion. It does not eliminate it. Without proxy-path
	// agent tokens (--require-agent-token), a fresh MCP session
	// is a new identity. With tokens on, the agent id is bound
	// to the token, and rotation of the session header alone
	// does not change it (see SECURITY.md).
	if px.IsContained(session, mcpID) {
		if r.Method == http.MethodPost {
			if !px.witness(session, "containment", "(session)", nil, "deny", "", agentID, w, body) {
				return
			}
		}
		http.Error(w, "ledgerline: session contained", http.StatusForbidden)
		return
	}

	// The broker owns its headers. A request carrying a
	// brokered header with a foreign value is denied before
	// anything else. Tool calls witness the denial. Other
	// traffic just fails. This refusal is a boundary rule.
	// Detect mode does not change it. The detect promise
	// covers policy rules only. A foreign credential must
	// never reach the ledger or the upstream.
	if px.broker != nil {
		if name := px.broker.ForeignHeader(r); name != "" {
			msg := "ledgerline: foreign credential in header " + name
			if r.Method == http.MethodPost {
				if isToolCall(body) {
					tool, _ := toolCallDetails(body)
					if _, ok := px.witnessPolicyDecision(session, tool, "deny", policy.ModePrevent.String(), agentID, w, body); !ok {
						return
					}
				}
				writeJSONRPCError(w, body, msg)
				return
			}
			http.Error(w, msg, http.StatusForbidden)
			return
		}
	}

	// Witness + police tool calls at the boundary.
	var claim *idemClaim
	if r.Method == http.MethodPost && isToolCall(body) {
		tool, args := toolCallDetails(body)
		// A brokered secret in the arguments is denied before
		// any witness that would record those arguments. The
		// secret must never reach the ledger, the hold queue,
		// or the proposal queue. This refusal is a boundary
		// rule. Detect mode does not change it. The detect
		// promise covers policy rules only.
		if px.broker != nil && px.broker.ContainsSecret(args) {
			if _, ok := px.witnessPolicyDecision(session, tool, "deny", policy.ModePrevent.String(), agentID, w, body); !ok {
				return
			}
			writeJSONRPCError(w, body, "ledgerline: tool arguments contain a brokered credential")
			return
		}
		// Decide first. The drift gate needs the rule mode.
		// DecideCall is pure. It writes nothing.
		decision, reason, mode := px.policyNow().DecideCall(tool, args)
		// Detect mode changes every restrictive action the same
		// way. The call always proceeds on the allow path. The
		// ledger records the would-be decision first, then the
		// tool_call that ran anyway. Both carry one decision
		// id. Hold in detect queues nothing and asks no human.
		// Contain in detect freezes nothing. Propose in detect
		// records a proposal marked detected and never queues
		// it. A human must never apply a call that already ran.
		detect := mode == policy.ModeDetect && decision != policy.Allow
		// Tools-drift gate: once a baseline exists, a tool
		// name outside it is denied until a human accepts
		// the new surface. Drift is a boundary gate, not a
		// policy rule. In prevent mode it denies. In detect
		// mode the denial is observed and the call runs.
		// The policy_decision carries deny with mode detect.
		// The tool_call below reuses its id. A drifted tool
		// is untrusted, but detect mode is the posture the
		// human chose for this tool. The ledger shows both
		// events, so the observation is explicit.
		driftDetected := false
		var decisionID string
		var ok bool
		if msg, denied := px.toolsGate(tool); denied {
			if mode == policy.ModeDetect {
				decisionID, ok = px.witnessPolicyDecision(session, tool, policy.Deny.String(), policy.ModeDetect.String(), agentID, w, body)
				if !ok {
					return
				}
				driftDetected = true
				detect = true
			} else {
				if !px.witness(session, "tools_drift", tool, nil, "deny", "", agentID, w, body) {
					return
				}
				writeJSONRPCError(w, body, msg)
				return
			}
		}
		// Idempotency lookup: a retry with a key is answered
		// from the journal when the journal says the call
		// must not run again. The claim itself waits until
		// the policy decision above stands. An allowed call claims
		// "started". A held call claims "held". Policy
		// denials, containments, and proposals leave no
		// record. A later retry re-evaluates current policy.
		if key := strings.TrimSpace(r.Header.Get(idemHeader)); key != "" {
			if len(key) > idemMaxKeyLen {
				writeJSONRPCError(w, body, "ledgerline: idempotency key too long")
				return
			}
			rec, found, err := px.ledger.IdemGet(session, key)
			if err != nil {
				writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
				return
			}
			if found {
				if rec.Tool != tool || rec.ArgsHash != idemArgsHash(args) {
					writeJSONRPCError(w, body, "ledgerline: idempotency key reused with different tool or arguments")
					return
				}
				if px.idemShortCircuit(w, body, session, rec, agentID) {
					return
				}
			}
			claim = &idemClaim{key: key, tool: tool, argsHash: idemArgsHash(args)}
		}
		if !driftDetected {
			decisionID, ok = px.witnessPolicyDecision(session, tool, decision.String(), mode.String(), agentID, w, body)
			if !ok {
				return
			}
		}
		switch decision {
		case policy.Deny:
			if detect {
				break
			}
			msg := "ledgerline: tool call denied by policy"
			if reason != "" {
				msg += ": " + reason
			}
			writeJSONRPCError(w, body, msg)
			return
		case policy.Hold:
			if detect {
				break
			}
			px.hold(w, r, session, body, tool, args, claim, agentID)
			return
		case policy.Contain:
			if detect {
				break
			}
			msg := "ledgerline: session contained by policy"
			if reason != "" {
				msg += ": " + reason
			}
			px.Contain(session, "", reason, agentID)
			writeJSONRPCError(w, body, msg)
			return
		case policy.Propose:
			if detect {
				// Record the proposal, marked detected. Do not
				// queue it. The call forwards below.
				if _, err := px.ledger.AppendDetailed(session, "proposal", tool, args, "propose", "", ledger.EventDetail{Mode: mode.String(), DecisionID: decisionID, AgentID: agentID}); err != nil {
					log.Printf("ledger write failed on proposal: %v", err)
					writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
					return
				}
				break
			}
			px.propose(w, session, body, tool, args, agentID)
			return
		}
		if claim != nil {
			// Claim "started" before forwarding. The atomic
			// claim is what stops a concurrent identical retry
			// from forwarding a second copy. A losing retry is
			// answered from the winner's record.
			now := time.Now().UTC()
			existing, claimed, err := px.claimIdem(ledger.IdempotencyRecord{Key: claim.key, SessionID: session, Tool: tool, ArgsHash: claim.argsHash, State: ledger.IdemStarted, CreatedAt: now, UpdatedAt: now})
			if err != nil {
				writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
				return
			}
			if !claimed {
				if existing.Tool != tool || existing.ArgsHash != claim.argsHash {
					writeJSONRPCError(w, body, "ledgerline: idempotency key reused with different tool or arguments")
				} else {
					px.idemShortCircuit(w, body, session, existing, agentID)
				}
				return
			}
		}
		// The tool_call is witnessed in forward, after the
		// last gates. A containment or drift denial at
		// forward time must never follow an allow. The
		// witness rides the request. forward writes it
		// after the gates pass and before the upstream
		// call. In detect mode the tool_call reuses the
		// policy_decision id. The pair links the would-be
		// decision to the call that ran anyway. A held call
		// carries its witness from its release path. The
		// same rule applies there: no allow before the
		// gates pass.
		r = withToolCallWitness(r, toolCallWitness{tool: tool, args: args, decisionID: decisionID, mode: mode.String(), agentID: agentID, detect: detect, driftDetected: driftDetected})
	}

	// A JSON-RPC batch could smuggle tool calls past the witness.
	// The gateway cannot classify the calls inside it. Batches
	// are refused at the boundary. The refusal is witnessed.
	// This refusal is a boundary rule. Detect mode does not
	// change it. The detect promise covers policy rules only.
	// A batch cannot be observed call by call, so it cannot run
	// under detect mode either.
	if r.Method == http.MethodPost && isBatch(body) {
		if _, ok := px.witnessPolicyDecision(session, "(batch)", policy.Deny.String(), policy.ModePrevent.String(), agentID, w, body); !ok {
			return
		}
		writeJSONRPCError(w, body, "ledgerline: batch requests are not accepted at this boundary")
		return
	}
	if r.Method == http.MethodPost && len(body) > 0 && !json.Valid(body) {
		log.Printf("ledgerline: forwarding unparseable POST body (%d bytes) unwitnessed", len(body))
	}

	px.forward(w, r, body, claim)
}

// isBatch reports whether the body is a JSON array (a JSON-RPC batch).
// trackInflight registers a cancellable upstream request under its
// session. untrackInflight removes it when the request finishes.
func (px *Proxy) trackInflight(session string, cancel context.CancelFunc) *inflightReq {
	req := &inflightReq{cancel: cancel}
	px.inflightMu.Lock()
	defer px.inflightMu.Unlock()
	if px.inflight == nil {
		px.inflight = map[string]map[*inflightReq]struct{}{}
	}
	set := px.inflight[session]
	if set == nil {
		set = map[*inflightReq]struct{}{}
		px.inflight[session] = set
	}
	set[req] = struct{}{}
	return req
}

func (px *Proxy) untrackInflight(session string, req *inflightReq) {
	px.inflightMu.Lock()
	defer px.inflightMu.Unlock()
	if set := px.inflight[session]; set != nil {
		delete(set, req)
		if len(set) == 0 {
			delete(px.inflight, session)
		}
	}
}

// cancelInflight aborts every in-flight upstream request for a
// session. Contain calls it.
func (px *Proxy) cancelInflight(session string) {
	px.inflightMu.Lock()
	set := px.inflight[session]
	delete(px.inflight, session)
	px.inflightMu.Unlock()
	for req := range set {
		req.cancel()
	}
}

func isBatch(body []byte) bool {
	return len(bytes.TrimSpace(body)) > 0 && bytes.TrimSpace(body)[0] == '['
}

// witness appends one event, failing closed. If the ledger cannot
// be written, the call does not pass the boundary. The agent id
// is empty when proxy-path auth is off.
func (px *Proxy) witness(session, kind, tool string, args json.RawMessage, decision, actor, agentID string, w http.ResponseWriter, body []byte) bool {
	if _, err := px.ledger.AppendDetailed(session, kind, tool, args, decision, actor, ledger.EventDetail{AgentID: agentID}); err != nil {
		log.Printf("ledger write failed: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return false
	}
	return true
}

// witnessDetailed appends one event with extra fields, failing
// closed. It mirrors witness.
func (px *Proxy) witnessDetailed(session, kind, tool string, args json.RawMessage, decision, actor string, detail ledger.EventDetail, w http.ResponseWriter, body []byte) bool {
	if _, err := px.ledger.AppendDetailed(session, kind, tool, args, decision, actor, detail); err != nil {
		log.Printf("ledger write failed: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return false
	}
	return true
}

// witnessPolicyDecision records one policy_decision event with
// its mode, a fresh decision id, and the policy hash. It also
// records the agent id. It returns the decision id. A follow-up
// tool_call in detect mode reuses the id, so the dashboard can
// link the pair. It fails closed like witness.
func (px *Proxy) witnessPolicyDecision(session, tool, decision, mode, agentID string, w http.ResponseWriter, body []byte) (string, bool) {
	id, err := newID()
	if err != nil {
		log.Printf("ledger write failed: cannot allocate decision id: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return "", false
	}
	detail := ledger.EventDetail{Mode: mode, DecisionID: id, PolicyHash: px.policyHashNow(), AgentID: agentID}
	if _, err := px.ledger.AppendDetailed(session, "policy_decision", tool, nil, decision, "", detail); err != nil {
		log.Printf("ledger write failed: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return "", false
	}
	return id, true
}

// appendPolicyDecision records one policy_decision event with
// its mode, a fresh decision id, and the policy hash. It also
// records the agent id. It is the hook endpoint form of
// witnessPolicyDecision. It returns the decision id. The caller
// answers the HTTP failure itself.
func (px *Proxy) appendPolicyDecision(session, tool, decision string, mode policy.Mode, agentID string) (string, error) {
	id, err := newID()
	if err != nil {
		return "", err
	}
	detail := ledger.EventDetail{Mode: mode.String(), DecisionID: id, PolicyHash: px.policyHashNow(), AgentID: agentID}
	if _, err := px.ledger.AppendDetailed(session, "policy_decision", tool, nil, decision, "", detail); err != nil {
		return "", err
	}
	return id, nil
}

// sessionOf reads the ledger session from the request. It defaults
// to the shared "default" session when the header is absent.
// "gateway" is reserved for the gateway's own rows. An agent
// session with that name would hide among system rows. The
// request is rejected instead of renamed. A rename would silently
// merge two agents into one session.
func sessionOf(r *http.Request) (string, error) {
	if s := r.Header.Get("X-Ledgerline-Session"); s != "" {
		if strings.EqualFold(s, "gateway") {
			return "", fmt.Errorf("ledgerline: session name %q is reserved", s)
		}
		return s, nil
	}
	return "default", nil
}

// toolCallWitness is the tool_call allow a call still owes the
// ledger. ServeHTTP builds it for a fresh call. release builds
// it for a held call. forward writes it after the last gates
// pass. A denial at forward time must never follow an allow.
type toolCallWitness struct {
	tool          string
	args          json.RawMessage
	decisionID    string
	mode          string
	agentID       string
	actor         string // approver name for a held call, empty otherwise
	detect        bool
	driftDetected bool // arrival already recorded this drift
}

// toolCallWitnessKey is the request context key for the pending
// tool_call witness. Only the fresh proxy path sets it.
type toolCallWitnessKey struct{}

func withToolCallWitness(r *http.Request, tw toolCallWitness) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), toolCallWitnessKey{}, tw))
}

func toolCallWitnessOf(r *http.Request) (toolCallWitness, bool) {
	tw, ok := r.Context().Value(toolCallWitnessKey{}).(toolCallWitness)
	return tw, ok
}

// forward passes the request upstream and streams the response back.
// The request is registered as in-flight under its session. Contain
// cancels it mid-flight. The gateway stops waiting and cuts the
// response. Nothing from it reaches the agent. Whether the upstream
// itself stops depends on it observing cancellation. A stream it
// already started does stop. The server notices the closed
// connection. A plain request still awaiting its first byte may run
// to completion server-side, with its result discarded. Cancelling
// never undoes a side effect the upstream already executed.
// forward also re-checks containment at its own entry. The hold
// release path reaches forward without passing the ServeHTTP gate.
// A session contained after its hold was approved must still never
// forward.
func (px *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte, claim *idemClaim) {
	session, err := sessionOf(r)
	if err != nil {
		writeJSONRPCError(w, body, err.Error())
		return
	}
	if px.IsContained(session, r.Header.Get("Mcp-Session-Id")) {
		if _, err := px.ledger.AppendDetailed(session, "containment", "(session)", nil, "deny", "", ledger.EventDetail{AgentID: agentIDOf(r)}); err != nil {
			log.Printf("ledger write failed on contained forward: %v", err)
		}
		if claim != nil {
			// Contained before running. The call never ran. A
			// retry runs fresh once uncontained.
			px.idemTransition(session, claim.key, ledger.IdemDiscarded, nil)
		}
		writeJSONRPCError(w, body, "ledgerline: session contained")
		return
	}

	// Drift re-check at the last point before upstream. A held
	// call waited while the surface changed. A concurrent
	// list can move it even for a fresh call. The gate the
	// call passed at arrival may no longer hold. A denied
	// release never ran. A keyed retry runs fresh (and hits
	// the gate again) instead of replaying a denial. In
	// detect mode the drift is observed and the call runs.
	// The tools_drift event carries mode detect, so a reader
	// can tell it apart from a denial. The allow the witness
	// below records is then true: the call ran. In prevent
	// mode the call is denied. No allow was witnessed yet
	// for a fresh call or a held call, so the ledger holds
	// no false allow. Both paths carry their witness here.
	if r.Method == http.MethodPost && isToolCall(body) {
		if tool, _ := toolCallDetails(body); tool != "" {
			if msg, denied := px.toolsGate(tool); denied {
				tw, hasWitness := toolCallWitnessOf(r)
				if hasWitness && tw.driftDetected {
					// The drift was already observed at
					// arrival as a policy_decision. Do not
					// record it twice. The call runs. The
					// allow below reuses that id.
				} else if hasWitness && tw.detect {
					if _, err := px.ledger.AppendDetailed(session, "tools_drift", tool, nil, "deny", "", ledger.EventDetail{Mode: policy.ModeDetect.String(), AgentID: agentIDOf(r)}); err != nil {
						log.Printf("ledger write failed on drift-denied forward: %v", err)
						if claim != nil {
							px.idemTransition(session, claim.key, ledger.IdemDiscarded, nil)
						}
						writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
						return
					}
				} else {
					if _, err := px.ledger.AppendDetailed(session, "tools_drift", tool, nil, "deny", "", ledger.EventDetail{AgentID: agentIDOf(r)}); err != nil {
						log.Printf("ledger write failed on drift-denied forward: %v", err)
					}
					if claim != nil {
						px.idemTransition(session, claim.key, ledger.IdemDiscarded, nil)
					}
					writeJSONRPCError(w, body, msg)
					return
				}
			}
		}
	}

	// Witness the tool_call now, after the last gates. A fresh
	// call and a held call both carry their witness in the
	// request. A witness failure closes the boundary. The call
	// never ran. Its journal entry must not block retries
	// as "started".
	if tw, hasWitness := toolCallWitnessOf(r); hasWitness {
		witnessed := false
		if tw.detect {
			witnessed = px.witnessDetailed(session, "tool_call", tw.tool, tw.args, policy.Allow.String(), tw.actor, ledger.EventDetail{Mode: tw.mode, DecisionID: tw.decisionID, AgentID: tw.agentID}, w, body)
		} else {
			witnessed = px.witness(session, "tool_call", tw.tool, tw.args, policy.Allow.String(), tw.actor, tw.agentID, w, body)
		}
		if !witnessed {
			if claim != nil {
				px.idemTransition(session, claim.key, ledger.IdemDiscarded, nil)
			}
			return
		}
	}

	// A keyed call is journaled as started before the upstream
	// sees it. If the process dies from here on, recovery marks
	// it unknown instead of losing it. A journal failure closes
	// the boundary rather than running unjournaled.
	var out http.ResponseWriter = w
	var capW *captureWriter
	if claim != nil {
		rec, found, err := px.ledger.IdemGet(session, claim.key)
		if err != nil || !found {
			writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
			return
		}
		rec.State = ledger.IdemStarted
		rec.UpdatedAt = time.Now().UTC()
		if err := px.ledger.IdemPut(rec); err != nil {
			writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
			return
		}
		capW = &captureWriter{ResponseWriter: w, buf: &limitedBuffer{cap: idemMaxBody}}
		out = capW
	}

	// A tools/list response is captured for drift observation.
	// It is how the gateway learns the upstream's current
	// surface. Nesting capture writers is safe. Each tees its
	// own buffer while passing bytes through.
	var listBuf *limitedBuffer
	if r.Method == http.MethodPost && isToolsList(body) {
		listBuf = &limitedBuffer{cap: maxListBytes}
		out = &captureWriter{ResponseWriter: out, buf: listBuf}
	}

	target := *px.upstream
	target.Path = singleJoin(px.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	req := px.trackInflight(session, cancel)
	defer px.untrackInflight(session, req)

	upReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusBadGateway)
		return
	}
	upReq.Header = r.Header.Clone()
	stripHopByHop(upReq.Header)
	// The agent token and the control-plane token never reach
	// upstream. The agent token proves identity to this
	// gateway only. The control-plane token guards this
	// gateway only. Neither belongs to the upstream server.
	// Authorization is stripped too: a client credential
	// must not leak to the upstream through the proxy.
	upReq.Header.Del(agentTokenHeader)
	upReq.Header.Del("Authorization")
	upReq.Header.Del("X-Ledgerline-Token")
	// Brokered headers are injected here. A foreign agent
	// value under a brokered name was already denied
	// before forwarding.
	if px.broker != nil {
		px.broker.InjectHeaders(upReq.Header)
	}

	resp, err := px.client.Do(upReq)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		if claim != nil {
			// No response arrived. The call may or may not
			// have executed upstream. Unknown, not completed.
			px.idemTransition(session, claim.key, ledger.IdemUnknown, nil)
		}
		return
	}
	defer resp.Body.Close()

	respHeader := resp.Header.Clone()
	stripHopByHop(respHeader)
	// Redaction changes the body length. The upstream's
	// Content-Length must not survive. Without it the
	// response is chunked. A shortened body cannot truncate
	// or hang the agent's read.
	redact := px.broker != nil && len(px.broker.secrets) > 0
	if redact {
		respHeader.Del("Content-Length")
	}
	for k, vs := range respHeader {
		for _, v := range vs {
			out.Header().Add(k, v)
		}
	}
	out.WriteHeader(resp.StatusCode)
	var copyErr error
	if redact {
		copyErr = px.broker.RedactCopy(out, resp.Body)
	} else {
		_, copyErr = io.Copy(out, resp.Body)
	}
	if claim != nil {
		if copyErr != nil {
			// The response did not arrive whole. The call may
			// have executed, but the agent never saw proof.
			px.idemTransition(session, claim.key, ledger.IdemUnknown, nil)
			return
		}
		// The response the agent saw is the journaled one.
		// It holds post-redaction bytes, or nothing when over
		// the cap.
		px.idemTransition(session, claim.key, ledger.IdemCompleted, func(rec *ledger.IdempotencyRecord) {
			rec.Status = capW.status
			rec.ContentType = resp.Header.Get("Content-Type")
			if capW.buf.overflow {
				rec.Body = nil
				rec.BodyTooLarge = true
			} else {
				rec.Body = capW.buf.buf
				rec.BodyTooLarge = false
			}
		})
	}
	if listBuf != nil && !listBuf.overflow && copyErr == nil {
		px.observeToolsList(listBuf.buf)
	} else if listBuf != nil && listBuf.overflow {
		log.Printf("tools/list response over %d bytes, ignored for baseline", maxListBytes)
	}
}

// hopByHop lists the connection-specific header names from
// RFC 7230 §6.1.
var hopByHop = []string{
	"Connection", "Keep-Alive", "Proxy-Connection",
	"Proxy-Authorization", "Proxy-Authenticate",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// stripHopByHop removes hop-by-hop headers: the fixed list plus any
// header named by the Connection header itself. They describe one
// connection. They must not cross the proxy. Forwarding them (a
// client's "Connection: close", say) makes strict upstreams reject
// otherwise valid requests.
func stripHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

func isToolCall(body []byte) bool {
	var m jsonRPC
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	return m.Method == "tools/call"
}

func toolCallDetails(body []byte) (string, json.RawMessage) {
	var m jsonRPC
	if err := json.Unmarshal(body, &m); err != nil {
		return "", nil
	}
	var p toolParams
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return "", nil
	}
	return p.Name, p.Arguments
}

// writeJSONRPCError answers with a protocol-shaped error. MCP
// clients see a proper JSON-RPC error instead of an HTTP failure.
// It uses HTTP 200, the usual JSON-RPC transport status.
func writeJSONRPCError(w http.ResponseWriter, body []byte, msg string) {
	writeJSONRPCErrorStatus(w, body, msg, http.StatusOK)
}

// writeJSONRPCErrorStatus answers with a protocol-shaped error
// and the given HTTP status. Auth rejections use 401.
func writeJSONRPCErrorStatus(w http.ResponseWriter, body []byte, msg string, status int) {
	var m jsonRPC
	_ = json.Unmarshal(body, &m)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      json.RawMessage(nullID(m.ID)),
		"error":   map[string]any{"code": -32000, "message": msg},
	})
}

func nullID(id json.RawMessage) []byte {
	if len(id) == 0 {
		return []byte("null")
	}
	return id
}

func singleJoin(a, b string) string {
	return strings.TrimSuffix(a, "/") + "/" + strings.TrimPrefix(b, "/")
}
