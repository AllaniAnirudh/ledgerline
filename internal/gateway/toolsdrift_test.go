package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// mutableToolsStub is an MCP server whose tool surface the test can
// change mid-run, the way a compromised or redeployed server would.
type mutableToolsStub struct {
	mu    sync.Mutex
	tools []listTool
	hits  atomic.Int32
	sse   bool
}

func (s *mutableToolsStub) set(tools []listTool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = tools
}

func (s *mutableToolsStub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m jsonRPC
	buf, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(buf, &m)
	s.mu.Lock()
	tools := append([]listTool(nil), s.tools...)
	sse := s.sse
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if m.Method == "tools/list" {
		payload, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 1,
			"result": map[string]any{"tools": tools},
		})
		if sse {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", payload)
			return
		}
		w.Write(payload)
		return
	}
	if m.Method == "tools/call" {
		s.hits.Add(1)
	}
	w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
}

func postList(t *testing.T, px *Proxy) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func toolsStatus(t *testing.T, px *Proxy) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/tools", nil)
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	var status map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	return status
}

func countEvents(t *testing.T, px *Proxy, kind, decision string) int {
	t.Helper()
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == kind && e.Decision == decision {
			n++
		}
	}
	return n
}

func TestToolsDriftEstablishAndGate(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}, {Name: "add"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	status := toolsStatus(t, px)
	if status["baseline"] == nil {
		t.Fatal("first tools/list should establish a baseline")
	}
	_, out := postToolHeaders(t, px, "add", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("baseline tool should be allowed, got %s", out)
	}
	before := stub.hits.Load()
	_, out = postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("unknown tool should be denied as drift, got %s", out)
	}
	if stub.hits.Load() != before {
		t.Fatalf("drift-denied call must not reach upstream")
	}
}

func TestToolsDriftWitnessAndAccept(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo", Description: "v1"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	stub.set([]listTool{{Name: "echo", Description: "v2"}, {Name: "evil"}})
	postList(t, px)
	if n := countEvents(t, px, "tools_drift", "drift"); n != 1 {
		t.Fatalf("changed surface should witness exactly one drift event, got %d", n)
	}
	status := toolsStatus(t, px)
	if status["drift"] != true {
		t.Fatalf("status should report drift, got %v", status)
	}
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("drifted tool should stay denied before acceptance, got %s", out)
	}
	if !strings.Contains(out, "added since baseline: evil") {
		t.Fatalf("denial should name what changed, got %s", out)
	}
	// Accept, then the next list becomes the new baseline.
	req := httptest.NewRequest(http.MethodPost, "/v1/tools/accept", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept should succeed, got %d", rec.Code)
	}
	postList(t, px)
	if n := countEvents(t, px, "tools_baseline", "reapprove"); n != 1 {
		t.Fatalf("accept + list should witness one reapprove, got %d", n)
	}
	status = toolsStatus(t, px)
	if status["drift"] != false {
		t.Fatalf("status should be clean after reapprove, got %v", status)
	}
	_, out = postToolHeaders(t, px, "evil", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("accepted tool should be allowed, got %s", out)
	}
}

func TestToolsDriftRemovalWitnessedNotEnforced(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "a"}, {Name: "b"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	stub.set([]listTool{{Name: "a"}})
	postList(t, px)
	if n := countEvents(t, px, "tools_drift", "drift"); n != 1 {
		t.Fatalf("removal should witness drift, got %d events", n)
	}
	_, out := postToolHeaders(t, px, "b", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("removed-but-baseline tool stays callable by design, got %s", out)
	}
}

func TestToolsDriftPersistence(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	store, err := ledger.OpenSQLite(filepath.Join(t.TempDir(), "drift.db"))
	if err != nil {
		t.Fatal(err)
	}
	px1, err := New(srv.URL, store, policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px1)
	// A fresh proxy on the same store inherits the baseline: a
	// restart must not grant the upstream amnesty.
	px2, err := New(srv.URL, store, policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, out := postToolHeaders(t, px2, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("restarted proxy should enforce the stored baseline, got %s", out)
	}
}

func TestToolsDriftProbe(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := px.ProbeToolsBaseline(); err != nil {
		t.Fatal(err)
	}
	if toolsStatus(t, px)["baseline"] == nil {
		t.Fatal("probe should establish a baseline")
	}
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("probed baseline should gate calls, got %s", out)
	}
}

func TestToolsDriftProbeFailureDefers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json at all`))
	}))
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := px.ProbeToolsBaseline(); err != nil {
		t.Fatalf("probe failure must not fail startup, got %v", err)
	}
	if toolsStatus(t, px)["baseline"] != nil {
		t.Fatal("unparseable probe must not establish a baseline")
	}
	_, out := postToolHeaders(t, px, "anything", `{}`, nil)
	if strings.Contains(out, "not in baseline") {
		t.Fatalf("with no baseline, calls stay allowed, got %s", out)
	}
}

func TestToolsDriftSSEList(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}, sse: true}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	if toolsStatus(t, px)["baseline"] == nil {
		t.Fatal("SSE tools/list should establish a baseline from its data payload")
	}
}

func TestToolsDriftSameListNoSecondEvent(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	postList(t, px)
	if n := countEvents(t, px, "tools_baseline", "establish"); n != 1 {
		t.Fatalf("identical list should not re-establish, got %d establish events", n)
	}
	if n := countEvents(t, px, "tools_drift", "drift"); n != 0 {
		t.Fatalf("identical list should not drift, got %d drift events", n)
	}
}
