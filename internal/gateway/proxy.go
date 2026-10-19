// Package gateway is the boundary: an HTTP proxy that sits between an
// MCP client (the agent) and the upstream MCP server.
//
// Every JSON-RPC tool call crossing the boundary is witnessed into the
// ledger and checked against policy before it is allowed through.
// Non-tool traffic is forwarded untouched.
//
// The agent is never trusted to log itself. The gateway is the trust
// root for everything it witnesses.
package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// Proxy forwards MCP traffic while witnessing and policing tool calls.
type Proxy struct {
	upstream *url.URL
	ledger   *ledger.Ledger
	policy   *policy.Policy
	client   *http.Client
}

// New builds a proxy for one upstream MCP server base URL.
func New(upstream string, l *ledger.Ledger, p *policy.Policy) (*Proxy, error) {
	u, err := url.Parse(strings.TrimSuffix(upstream, "/"))
	if err != nil {
		return nil, err
	}
	return &Proxy{upstream: u, ledger: l, policy: p, client: &http.Client{}}, nil
}

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
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	r.Body.Close()

	session := r.Header.Get("X-Ledgerline-Session")
	if session == "" {
		session = "default"
	}

	// Witness + police tool calls at the boundary.
	if r.Method == http.MethodPost && isToolCall(body) {
		tool, args := toolCallDetails(body)
		d := px.policy.Decide(tool)
		px.ledger.Append(session, "policy_decision", tool, nil, d.String(), "")
		if d != policy.Allow {
			px.ledger.Append(session, "approval", tool, args, d.String(), "")
			writeJSONRPCError(w, body, "ledgerline: tool call "+d.String()+" by policy")
			return
		}
		px.ledger.Append(session, "tool_call", tool, args, d.String(), "")
	}

	px.forward(w, r, body)
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

	resp, err := px.client.Do(out)
	if err != nil {
		http.Error(w, "upstream unreachable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
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
