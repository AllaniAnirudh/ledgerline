package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Tests for the hook bridge agent token (M4) and the reserved
// session name (M5). The gateway validates the agent token. The
// bridge only carries it. Standalone mode stays unattributed.

func TestFixDecideHookGatewaySendsAgentToken(t *testing.T) {
	var sawAPI, sawAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAPI = r.Header.Get("X-Ledgerline-Token")
		sawAgent = r.Header.Get("X-Ledgerline-Agent-Token")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()
	out, err := decideHookGatewayWithAgent(srv.URL, "tok", "agt", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || !out.allow {
		t.Fatalf("allow answer should allow, got %+v %v", out, err)
	}
	if sawAPI != "tok" {
		t.Fatalf("api token = %q, want tok", sawAPI)
	}
	if sawAgent != "agt" {
		t.Fatalf("agent token = %q, want agt", sawAgent)
	}
}

func TestFixDecideHookGatewayWithoutAgentToken(t *testing.T) {
	var sawAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAgent = r.Header.Get("X-Ledgerline-Agent-Token")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()
	out, err := decideHookGateway(srv.URL, "tok", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || !out.allow {
		t.Fatalf("allow answer should allow, got %+v %v", out, err)
	}
	if sawAgent != "" {
		t.Fatalf("agent token = %q, want no header without a token", sawAgent)
	}
}

func TestFixRunHookRejectsGatewaySession(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{"tool":"bash","args":{},"session":"gateway"}`))
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	err = runHook([]string{"--harness", "generic", "--gateway", srv.URL})
	if err == nil {
		t.Fatal("session gateway should block")
	}
	var ec exitCodeError
	if !errors.As(err, &ec) || ec.code != 2 {
		t.Fatalf("error = %v, want exit code 2", err)
	}
	if hits != 0 {
		t.Fatalf("rejected session must never reach the gateway, hits=%d", hits)
	}
}

func TestFixRunHookGatewaySessionFlagRejected(t *testing.T) {
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Write([]byte(`{"tool":"bash","args":{}}`))
	_ = w.Close()
	os.Stdin = r
	defer func() { os.Stdin = oldStdin }()
	err = runHook([]string{"--harness", "generic", "--session", "gateway", "--db", ""})
	if err == nil {
		t.Fatal("session gateway should block")
	}
	if !strings.Contains(err.Error(), "exit code 2") {
		t.Fatalf("error = %v, want exit code 2", err)
	}
}
