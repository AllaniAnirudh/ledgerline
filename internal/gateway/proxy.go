// Package gateway is the boundary: an HTTP proxy that sits between an
// MCP client (the agent) and the upstream MCP server.
//
// Every JSON-RPC tool call crossing the boundary is witnessed into the
// ledger and checked against policy before it is allowed through.
// Non-tool traffic is forwarded untouched.
//
// The agent is never trusted to log itself. The gateway is the trust
// root for everything it witnesses. If the ledger cannot be written,
// the boundary fails closed: no witness, no passage.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// maxBodyBytes caps one proxied request body. Tool calls are small;
// the cap exists so a client cannot make the boundary buffer an
// unbounded request into memory.
const maxBodyBytes = 10 << 20

// Proxy forwards MCP traffic while witnessing and policing tool calls.
type Proxy struct {
	upstream  *url.URL
	ledger    ledger.Store
	policy    *policy.Policy
	client    *http.Client
	approvals *Approvals
	proposals *Proposals
	apiToken  string
	approvers map[string]string // token -> approver name

	containedMu   sync.Mutex
	contained     map[string]containedSession
	containedMCP  map[string]bool            // upstream MCP session ids frozen with their sessions
	observed      map[string]map[string]bool // ledger session -> MCP session ids seen on it
	upstreamPin   string
	pinConfigured bool

	inflightMu sync.Mutex
	inflight   map[string]map[*inflightReq]struct{}
}

// inflightReq is one cancellable upstream request. It is keyed by
// pointer because a CancelFunc itself is not a map key.
type inflightReq struct {
	cancel context.CancelFunc
}

// SetAPIToken guards the /v1 control plane. When a token is set,
// every /v1 request must carry it as "Authorization: Bearer <token>"
// or the X-Ledgerline-Token header. Empty means no check (local use
// only; the control plane can approve held calls, so guard it before
// exposing the gateway beyond localhost).
func (px *Proxy) SetAPIToken(t string) { px.apiToken = t }

// SetApproverToken binds one token to one approver name. A decision
// made with an approver token is recorded in the ledger under the
// bound name; the request body cannot override it. Approver tokens
// also pass the control-plane token check.
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

// tokenEqual compares two tokens in constant time (via digests, so
// length does not leak either).
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

// approverActor returns the name bound to the request's token, when
// the request authenticated with a per-approver token.
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
	return &Proxy{upstream: u, ledger: l, policy: p, client: &http.Client{}, approvals: NewApprovals(), proposals: NewProposals()}, nil
}

// Approvals exposes the pending human-approval queue.
func (px *Proxy) Approvals() *Approvals { return px.approvals }

// Proposals exposes the pending out-of-band proposal queue.
func (px *Proxy) Proposals() *Proposals { return px.proposals }

// SetUpstreamPin records the pinned upstream identity for the
// /v1/upstream endpoint. Empty means pinning is not configured.
func (px *Proxy) SetUpstreamPin(pin string) {
	if pin == "" {
		return
	}
	px.upstreamPin = pin
	px.pinConfigured = true
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
	if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/replay" || r.URL.Path == "/approvals" {
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

	session := sessionOf(r)
	mcpID := r.Header.Get("Mcp-Session-Id")
	px.observeMCP(session, mcpID)

	// A contained session is cut off entirely: no tool call, no
	// list, no other proxied traffic passes. The control plane
	// above is unaffected, so a human can still inspect the
	// session, and it stays contained until a new gateway start.
	// Containment holds only while this gateway process lives: it
	// is a session freeze, not a kill switch that survives a
	// gateway restart. It is keyed on the ledger session AND on
	// every upstream MCP session id observed on it, so rotating
	// the ledger header alone does not evade it: the agent must
	// also abandon its upstream MCP session. That raises the cost
	// of evasion; it does not eliminate it, because the proxy path
	// is unauthenticated by design and a fresh MCP session is a
	// new identity. Full binding needs proxy-path client auth,
	// which this build does not add (see SECURITY.md).
	if px.IsContained(session, mcpID) {
		if r.Method == http.MethodPost {
			if !px.witness(session, "containment", "(session)", nil, "deny", "", w, body) {
				return
			}
		}
		http.Error(w, "ledgerline: session contained", http.StatusForbidden)
		return
	}

	// Witness + police tool calls at the boundary.
	if r.Method == http.MethodPost && isToolCall(body) {
		tool, args := toolCallDetails(body)
		decision, reason := px.policy.DecideCall(tool, args)
		if !px.witness(session, "policy_decision", tool, nil, decision.String(), "", w, body) {
			return
		}
		switch decision {
		case policy.Deny:
			msg := "ledgerline: tool call denied by policy"
			if reason != "" {
				msg += ": " + reason
			}
			writeJSONRPCError(w, body, msg)
			return
		case policy.Hold:
			px.hold(w, r, session, body, tool, args)
			return
		case policy.Contain:
			msg := "ledgerline: session contained by policy"
			if reason != "" {
				msg += ": " + reason
			}
			px.Contain(session, "", reason)
			writeJSONRPCError(w, body, msg)
			return
		case policy.Propose:
			px.propose(w, session, body, tool, args)
			return
		}
		if !px.witness(session, "tool_call", tool, args, policy.Allow.String(), "", w, body) {
			return
		}
	}

	// A JSON-RPC batch could smuggle tool calls past the witness:
	// the gateway cannot classify the calls inside it, so batches
	// are refused at the boundary and the refusal is witnessed.
	if r.Method == http.MethodPost && isBatch(body) {
		if !px.witness(session, "policy_decision", "(batch)", nil, policy.Deny.String(), "", w, body) {
			return
		}
		writeJSONRPCError(w, body, "ledgerline: batch requests are not accepted at this boundary")
		return
	}
	if r.Method == http.MethodPost && len(body) > 0 && !json.Valid(body) {
		log.Printf("ledgerline: forwarding unparseable POST body (%d bytes) unwitnessed", len(body))
	}

	px.forward(w, r, body)
}

// isBatch reports whether the body is a JSON array (a JSON-RPC batch).
// trackInflight registers a cancellable upstream request under its
// session; untrackInflight removes it when the request finishes.
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
// session. Called by Contain.
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

// witness appends one event, failing closed: if the ledger cannot be
// written, the call does not pass the boundary.
func (px *Proxy) witness(session, kind, tool string, args json.RawMessage, decision, actor string, w http.ResponseWriter, body []byte) bool {
	if _, err := px.ledger.Append(session, kind, tool, args, decision, actor); err != nil {
		log.Printf("ledger write failed: %v", err)
		writeJSONRPCError(w, body, "ledgerline: ledger unavailable, boundary closed")
		return false
	}
	return true
}

// sessionOf reads the ledger session from the request, defaulting
// to the shared "default" session when the header is absent.
func sessionOf(r *http.Request) string {
	if s := r.Header.Get("X-Ledgerline-Session"); s != "" {
		return s
	}
	return "default"
}

// forward passes the request upstream and streams the response back.
// The request is registered as in-flight under its session, so
// Contain cancels it mid-flight: the gateway stops waiting and
// cuts the response, so nothing from it reaches the agent. Whether
// the upstream itself stops depends on it observing cancellation:
// a stream it already started does (the server notices the closed
// connection), while a plain request still awaiting its first byte
// may run to completion server-side, with its result discarded.
// Cancelling never undoes a side effect the upstream already
// executed.
// forward also re-checks containment at its own entry: the hold
// release path reaches forward without passing the ServeHTTP gate,
// so a session contained after its hold was approved must still
// never forward.
func (px *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	session := sessionOf(r)
	if px.IsContained(session, r.Header.Get("Mcp-Session-Id")) {
		if _, err := px.ledger.Append(session, "containment", "(session)", nil, "deny", ""); err != nil {
			log.Printf("ledger write failed on contained forward: %v", err)
		}
		writeJSONRPCError(w, body, "ledgerline: session contained")
		return
	}

	target := *px.upstream
	target.Path = singleJoin(px.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	req := px.trackInflight(session, cancel)
	defer px.untrackInflight(session, req)

	out, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad upstream request", http.StatusBadGateway)
		return
	}
	out.Header = r.Header.Clone()
	stripHopByHop(out.Header)

	resp, err := px.client.Do(out)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respHeader := resp.Header.Clone()
	stripHopByHop(respHeader)
	for k, vs := range respHeader {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
// connection and must not cross the proxy; forwarding them (a
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

// writeJSONRPCError answers with a protocol-shaped error so MCP clients
// see a proper JSON-RPC error instead of an HTTP failure.
func writeJSONRPCError(w http.ResponseWriter, body []byte, msg string) {
	var m jsonRPC
	_ = json.Unmarshal(body, &m)
	w.Header().Set("Content-Type", "application/json")
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
