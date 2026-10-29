package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

func keyed(t *testing.T, px *Proxy, tool, args, key string) (int, string) {
	t.Helper()
	return postToolHeaders(t, px, tool, args, map[string]string{idemHeader: key})
}

func TestIdemReplay(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, nil))
	_, first := keyed(t, px, "read_file", `{}`, "key-1")
	_, second := keyed(t, px, "read_file", `{}`, "key-1")
	if first != second {
		t.Fatalf("replay should return the identical response, got %q then %q", first, second)
	}
	if hits.Load() != 1 {
		t.Fatalf("replay must not reach upstream, got %d hits", hits.Load())
	}
}

func TestIdemMismatch(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, nil))
	keyed(t, px, "read_file", `{}`, "key-1")
	_, body := keyed(t, px, "read_file", `{"x":1}`, "key-1")
	if !strings.Contains(body, "different tool or arguments") {
		t.Fatalf("same key with different arguments should be denied, got %s", body)
	}
	_, body = keyed(t, px, "other_tool", `{}`, "key-1")
	if !strings.Contains(body, "different tool or arguments") {
		t.Fatalf("same key with a different tool should be denied, got %s", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("mismatched retries must not reach upstream, got %d hits", hits.Load())
	}
}

func TestIdemInFlight(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slow":true}}`))
	}))
	t.Cleanup(upstream.Close)
	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	type res struct {
		code int
		body string
	}
	firstCh := make(chan res, 1)
	go func() {
		code, body := keyed(t, px, "read_file", `{}`, "key-slow")
		firstCh <- res{code, body}
	}()
	// Wait until the first request is upstream, then retry.
	deadline := time.Now().Add(5 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if hits.Load() == 0 {
		t.Fatal("first request never reached upstream")
	}
	_, body := keyed(t, px, "read_file", `{}`, "key-slow")
	if !strings.Contains(body, "already in flight") {
		t.Fatalf("concurrent retry should get in-flight, got %s", body)
	}
	close(release)
	first := <-firstCh
	if !strings.Contains(first.body, `"slow":true`) {
		t.Fatalf("first request should complete upstream, got %s", first.body)
	}
	_, third := keyed(t, px, "read_file", `{}`, "key-slow")
	if third != first.body {
		t.Fatalf("retry after completion should replay, got %q", third)
	}
	if hits.Load() != 1 {
		t.Fatalf("exactly one upstream execution expected, got %d", hits.Load())
	}
}

func TestIdemHeldRetry(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, []string{"held_tool"}))
	type res struct {
		code int
		body string
	}
	firstCh := make(chan res, 1)
	go func() {
		code, body := keyed(t, px, "held_tool", `{}`, "key-held")
		firstCh <- res{code, body}
	}()
	var approvalID string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list := px.Approvals().List()
		if len(list) == 1 {
			approvalID = list[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approvalID == "" {
		t.Fatal("held call never queued")
	}
	_, body := keyed(t, px, "held_tool", `{}`, "key-held")
	if !strings.Contains(body, "already held") || !strings.Contains(body, approvalID) {
		t.Fatalf("retry while held should name the same approval, got %s", body)
	}
	if len(px.Approvals().List()) != 1 {
		t.Fatalf("retry must not queue a second hold, got %d", len(px.Approvals().List()))
	}
	if !px.Approvals().Decide(approvalID, true, "tester") {
		t.Fatal("approve failed")
	}
	first := <-firstCh
	if !strings.Contains(first.body, `"ok":true`) {
		t.Fatalf("approved held call should forward, got %s", first.body)
	}
	_, third := keyed(t, px, "held_tool", `{}`, "key-held")
	if third != first.body {
		t.Fatalf("retry after approval should replay, got %q", third)
	}
	if hits.Load() != 1 {
		t.Fatalf("exactly one upstream execution expected, got %d", hits.Load())
	}
}

func TestIdemDenyReplay(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, []string{"held_tool"}))
	type res struct {
		code int
		body string
	}
	firstCh := make(chan res, 1)
	go func() {
		code, body := keyed(t, px, "held_tool", `{}`, "key-deny")
		firstCh <- res{code, body}
	}()
	var approvalID string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		list := px.Approvals().List()
		if len(list) == 1 {
			approvalID = list[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if approvalID == "" {
		t.Fatal("held call never queued")
	}
	if !px.Approvals().Decide(approvalID, false, "tester") {
		t.Fatal("deny failed")
	}
	<-firstCh
	_, body := keyed(t, px, "held_tool", `{}`, "key-deny")
	if !strings.Contains(body, "previously denied") {
		t.Fatalf("retry after deny should replay the denial, got %s", body)
	}
	if len(px.Approvals().List()) != 0 {
		t.Fatalf("denied retry must not queue a new hold")
	}
	if hits.Load() != 0 {
		t.Fatalf("denied call must never reach upstream, got %d", hits.Load())
	}
}

func TestIdemUnknownRecoveryAndResolve(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}))
	t.Cleanup(upstream.Close)
	store, err := ledger.OpenSQLite(filepath.Join(t.TempDir(), "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// A call that was started when the process died.
	if err := store.IdemPut(ledger.IdempotencyRecord{Key: "key-crash", SessionID: "test-session", Tool: "read_file", ArgsHash: idemArgsHash([]byte(`{}`)), State: ledger.IdemStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	px, err := New(upstream.URL, store, policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	rec, found, err := store.IdemGet("test-session", "key-crash")
	if err != nil || !found || rec.State != ledger.IdemUnknown {
		t.Fatalf("startup should flip started to unknown, got %+v found=%v err=%v", rec, found, err)
	}
	_, body := keyed(t, px, "read_file", `{}`, "key-crash")
	if !strings.Contains(body, "outcome unknown") {
		t.Fatalf("unknown retry should demand resolution, got %s", body)
	}
	// Resolve as not-executed: the retry runs fresh.
	resolve := func(key, resolution string) (int, string) {
		t.Helper()
		payload := `{"session":"test-session","key":"` + key + `","resolution":"` + resolution + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/idempotency/resolve", strings.NewReader(payload))
		rec := httptest.NewRecorder()
		px.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	if code, _ := resolve("key-crash", "not-executed"); code != http.StatusOK {
		t.Fatalf("resolve not-executed should succeed, got %d", code)
	}
	_, body = keyed(t, px, "read_file", `{}`, "key-crash")
	if !strings.Contains(body, `"ok":true`) {
		t.Fatalf("retry after not-executed resolve should forward, got %s", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("one upstream execution expected after resolve, got %d", hits.Load())
	}
	// A second unknown record, resolved as executed, never re-forwards.
	if err := store.IdemPut(ledger.IdempotencyRecord{Key: "key-ran", SessionID: "test-session", Tool: "read_file", ArgsHash: idemArgsHash([]byte(`{}`)), State: ledger.IdemUnknown, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if code, _ := resolve("key-ran", "executed"); code != http.StatusOK {
		t.Fatalf("resolve executed should succeed, got %d", code)
	}
	_, body = keyed(t, px, "read_file", `{}`, "key-ran")
	if !strings.Contains(body, "previously executed") {
		t.Fatalf("retry after executed resolve should be refused, got %s", body)
	}
	if hits.Load() != 1 {
		t.Fatalf("executed resolve must not re-forward, got %d hits", hits.Load())
	}
}

func TestIdemTooLargeNotReplayed(t *testing.T) {
	var hits atomic.Int32
	big := strings.Repeat("x", 2<<20)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + big + `"}`))
	}))
	t.Cleanup(upstream.Close)
	px, err := New(upstream.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, first := keyed(t, px, "read_file", `{}`, "key-big")
	if len(first) < 2<<20 {
		t.Fatalf("large response should still reach the agent, got %d bytes", len(first))
	}
	_, second := keyed(t, px, "read_file", `{}`, "key-big")
	if !strings.Contains(second, "too large to replay") {
		t.Fatalf("oversize retry should be refused, got %.100s", second)
	}
	if hits.Load() != 1 {
		t.Fatalf("oversize call must execute exactly once, got %d", hits.Load())
	}
}

func TestIdemKeyTooLong(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, nil))
	_, body := keyed(t, px, "read_file", `{}`, strings.Repeat("k", 300))
	if !strings.Contains(body, "too long") {
		t.Fatalf("oversize key should be denied, got %s", body)
	}
	if hits.Load() != 0 {
		t.Fatalf("oversize key must not reach upstream")
	}
}

func TestIdemNoKeyIsUnchanged(t *testing.T) {
	px, hits := testProxyPolicy(t, policy.New(nil, nil))
	postToolHeaders(t, px, "read_file", `{}`, nil)
	postToolHeaders(t, px, "read_file", `{}`, nil)
	if hits.Load() != 2 {
		t.Fatalf("unkeyed identical calls both forward, got %d hits", hits.Load())
	}
}
