package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tests for the hook gateway response cap (L-N7). The bridge
// reads the gateway answer through the same 1 MiB capped
// helpers as the other CLI calls. An oversize answer is
// rejected, not read into memory without bound.

func TestFixHookGatewayOversizeAnswerRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxGatewayResponseBytes+1)))
	}))
	defer srv.Close()
	_, err := decideHookGateway(srv.URL, "tok", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("oversize gateway answer should fail")
	}
	if !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversize error = %q, want the byte limit", err.Error())
	}
}

func TestFixHookGatewayOversizeErrorTruncated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("e", maxGatewayResponseBytes+100)))
	}))
	defer srv.Close()
	_, err := decideHookGateway(srv.URL, "tok", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err == nil {
		t.Fatal("oversize gateway error should fail")
	}
	if !strings.HasPrefix(err.Error(), "gateway: ") {
		t.Fatalf("oversize error = %q, want the gateway message", err.Error())
	}
	if len(err.Error()) > maxGatewayResponseBytes+64 {
		t.Fatalf("oversize error is %d bytes, want it capped near 1 MiB", len(err.Error()))
	}
}

func TestFixHookGatewayAnswerAtCapPasses(t *testing.T) {
	body := `{"decision":"allow"}` + strings.Repeat(" ", maxGatewayResponseBytes-len(`{"decision":"allow"}`))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	out, err := decideHookGateway(srv.URL, "tok", time.Second, "s1", "bash", json.RawMessage(`{}`))
	if err != nil || !out.allow {
		t.Fatalf("answer at the cap should allow, got %+v %v", out, err)
	}
}
