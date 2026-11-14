package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
	"github.com/AllaniAnirudh/ledgerline/internal/token"
)

// postToolBearer sends one tools/call with the token as
// Authorization: Bearer.
func postToolBearer(t *testing.T, px *Proxy, tool, session, tok string) int {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", session)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	return rec.Code
}

// mintFutureToken signs a token whose issue time sits two
// minutes in the future. Issue never mints one. The test
// signs by hand with the same HMAC-SHA256 form.
func mintFutureToken(t *testing.T) string {
	t.Helper()
	now := time.Now().UTC().Unix()
	claims := map[string]any{
		"agent_id": "agent-1", "owner": "buppy",
		"iat": now + 120, "exp": now + 3600, "jti": "future-1",
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	part := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, dashboardKey)
	mac.Write([]byte(part))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return part + "." + sig
}

func TestAgentBearerTokenAccepted(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	tok := mintAgent(t, "agent-1", time.Hour)
	if code := postToolBearer(t, px, "read_file", "s1", tok); code != http.StatusOK {
		t.Fatalf("Bearer token: want 200, got %d", code)
	}
}

func TestAgentBearerTokenRejected(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	other, _, err := token.Issue([]byte("fedcba9876543210fedcba9876543210"), "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if code := postToolBearer(t, px, "read_file", "s1", other); code != http.StatusUnauthorized {
		t.Fatalf("wrong-key Bearer: want 401, got %d", code)
	}
	// A non-Bearer scheme carries no agent token.
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "s1")
	req.Header.Set("Authorization", "Basic "+mintAgent(t, "agent-1", time.Hour))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("Basic scheme: want 401, got %d", rec.Code)
	}
}

func TestCustomHeaderWinsOverBearer(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	valid := mintAgent(t, "agent-1", time.Hour)
	other, _, err := token.Issue([]byte("fedcba9876543210fedcba9876543210"), "agent-1", "buppy", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{}}}`
	call := func(custom, bearer string) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
		req.Header.Set("X-Ledgerline-Session", "s1")
		if custom != "" {
			req.Header.Set(agentTokenHeader, custom)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := call(valid, other); code != http.StatusOK {
		t.Fatalf("valid custom plus bad Bearer: want 200, got %d", code)
	}
	if code := call(other, valid); code != http.StatusUnauthorized {
		t.Fatalf("bad custom plus valid Bearer: want 401, got %d", code)
	}
}

func TestAudienceBindsTokenToOneGateway(t *testing.T) {
	pxA, _ := authProxy(t, policy.New(nil, nil))
	pxB, _ := authProxy(t, policy.New(nil, nil))
	bound, _, err := token.IssueWithAudience(dashboardKey, "agent-1", "buppy", time.Hour, pxA.tokenAudience())
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := postToolAuth(t, pxA, "read_file", "s1", bound); code != http.StatusOK {
		t.Fatalf("bound token on its gateway: want 200, got %d", code)
	}
	if code, _ := postToolAuth(t, pxB, "read_file", "s1", bound); code != http.StatusUnauthorized {
		t.Fatalf("bound token on another gateway: want 401, got %d", code)
	}
	// A legacy token with no audience still passes on both.
	// It expires within 7 days of minting.
	legacy := mintAgent(t, "agent-1", time.Hour)
	if code, _ := postToolAuth(t, pxA, "read_file", "s1", legacy); code != http.StatusOK {
		t.Fatalf("legacy token on A: want 200, got %d", code)
	}
	if code, _ := postToolAuth(t, pxB, "read_file", "s1", legacy); code != http.StatusOK {
		t.Fatalf("legacy token on B: want 200, got %d", code)
	}
}

func TestFutureIatRejectedAtGateway(t *testing.T) {
	px, _ := authProxy(t, policy.New(nil, nil))
	if code, _ := postToolAuth(t, px, "read_file", "s1", mintFutureToken(t)); code != http.StatusUnauthorized {
		t.Fatalf("future issue time: want 401, got %d", code)
	}
}

func TestRevokePersistFailureStillRevokes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)
	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(2 * time.Second)
	// The revocation file sits in a directory that does not
	// exist. Every persist fails. The in-memory revocation
	// must still stand.
	revokeFile := filepath.Join(t.TempDir(), "no-such-dir", "revoked.json")
	if err := px.SetTokenKey(dashboardKey, revokeFile); err != nil {
		t.Fatal(err)
	}
	px.SetRequireAgentToken(true)
	px.SetAPIToken("s3cret")
	tok := mintAgent(t, "agent-1", time.Hour)
	claims, err := token.Validate(dashboardKey, tok)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"jti":"` + claims.ID + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/tokens/revoke", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Token", "s3cret")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke with failing persist: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["ok"] != true || out["persisted"] != false {
		t.Fatalf("revoke should report ok true and persisted false, got %v", out)
	}
	if out["persist_error"] == nil || out["persist_error"] == "" {
		t.Fatalf("revoke should name the persist error, got %v", out)
	}
	if _, err := os.Stat(revokeFile); !os.IsNotExist(err) {
		t.Fatalf("revocation file should not exist, stat gave %v", err)
	}
	// The token is rejected even though the file never wrote.
	if code, _ := postToolAuth(t, px, "read_file", "s1", tok); code != http.StatusUnauthorized {
		t.Fatalf("revoked with failing persist: want 401, got %d", code)
	}
}
