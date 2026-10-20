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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

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
	apiToken  string
	approvers map[string]string // token -> approver name
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
	return &Proxy{upstream: u, ledger: l, policy: p, client: &http.Client{}, approvals: NewApprovals()}, nil
}

// Approvals exposes the pending human-approval queue.
func (px *Proxy) Approvals() *Approvals { return px.approvals }

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

	session := r.Header.Get("X-Ledgerline-Session")
	if session == "" {
		session = "default"
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

// forward passes the request upstream and streams the response back.
func (px *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	target := *px.upstream
	target.Path = singleJoin(px.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	out, err := http.NewRequest(r.Method, target.String(), bytes.NewReader(body))
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
