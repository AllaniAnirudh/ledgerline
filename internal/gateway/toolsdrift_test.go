package gateway

import (
	"database/sql"
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
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
	_ "modernc.org/sqlite"
)

// mutableToolsStub is an MCP server. The test can change its tool
// surface mid-run, the way a compromised or redeployed server
// would.
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
	// Accept. Then the next list becomes the new baseline.
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
	// A fresh proxy on the same store inherits the baseline. A
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

func baselineToolNames(t *testing.T, px *Proxy) []string {
	t.Helper()
	status := toolsStatus(t, px)
	baseline, ok := status["baseline"].(map[string]any)
	if !ok {
		return nil
	}
	raw, _ := baseline["tools"].([]any)
	names := make([]string, 0, len(raw))
	for _, n := range raw {
		if s, ok := n.(string); ok {
			names = append(names, s)
		}
	}
	return names
}

func hasName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// pagedStub serves tools/list in two pages. Page 1 carries a
// nextCursor. Page 2 completes the surface.
func pagedStub(w http.ResponseWriter, r *http.Request) {
	var m jsonRPC
	buf, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(buf, &m)
	if m.Method != "tools/list" {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
		return
	}
	var params struct {
		Cursor string `json:"cursor"`
	}
	_ = json.Unmarshal(m.Params, &params)
	tools := []listTool{{Name: "echo"}}
	next := ""
	if params.Cursor == "" {
		tools = []listTool{{Name: "add"}}
		next = "p2"
	}
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1,
		"result": map[string]any{"tools": tools, "nextCursor": next},
	})
	w.Write(payload)
}

func TestToolsDriftPaginationProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(pagedStub))
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := px.ProbeToolsBaseline(); err != nil {
		t.Fatal(err)
	}
	names := baselineToolNames(t, px)
	if !hasName(names, "add") || !hasName(names, "echo") {
		t.Fatalf("probe should follow cursors to the full surface, got %v", names)
	}
	_, out := postToolHeaders(t, px, "echo", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("page-2 tool must be callable, got %s", out)
	}
}

func TestToolsDriftPartialPageIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(pagedStub))
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	if toolsStatus(t, px)["baseline"] != nil {
		t.Fatal("a partial page passing through must not establish a baseline")
	}
	_, out := postToolHeaders(t, px, "add", `{}`, nil)
	if strings.Contains(out, "not in baseline") {
		t.Fatalf("with no baseline, calls stay allowed, got %s", out)
	}
}

func TestToolsDriftHoldReleaseAfterRebaseline(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "x"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, []string{"x"}))
	if err != nil {
		t.Fatal(err)
	}
	px.Approvals().SetTimeout(10 * time.Second)
	postList(t, px)
	done := make(chan map[string]any, 1)
	go func() {
		_, out := postToolHeaders(t, px, "x", `{}`, nil)
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		done <- m
	}()
	var id string
	for i := 0; i < 100 && id == ""; i++ {
		time.Sleep(20 * time.Millisecond)
		if list := px.Approvals().List(); len(list) > 0 {
			id = list[0].ID
		}
	}
	if id == "" {
		t.Fatal("held call never appeared")
	}
	// The surface moves without x. A human accepts it.
	stub.set([]listTool{{Name: "y"}})
	px.SetToolsReapprovePending("tester")
	postList(t, px)
	if n := countEvents(t, px, "tools_baseline", "reapprove"); n != 1 {
		t.Fatalf("re-baseline should witness one reapprove, got %d", n)
	}
	// Approving the stale hold must not forward x.
	req := httptest.NewRequest(http.MethodPost, "/v1/approvals/"+id+"/decision", strings.NewReader(`{"decision":"approve","actor":"tester"}`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decision should succeed, got %d", rec.Code)
	}
	out := <-done
	errObj, _ := out["error"].(map[string]any)
	msg, _ := errObj["message"].(string)
	if !strings.Contains(msg, "not in baseline") {
		t.Fatalf("stale hold approved after re-baseline should be drift-denied, got %v", out)
	}
	if stub.hits.Load() != 0 {
		t.Fatalf("drift-denied release must not reach upstream, hits=%d", stub.hits.Load())
	}
}

func TestToolsDriftAcceptAuth(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.SetAPIToken("tok")
	req := httptest.NewRequest(http.MethodPost, "/v1/tools/accept", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("accept without token: want 401, got %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/v1/tools/accept", strings.NewReader(`{}`))
	req.Header.Set("X-Ledgerline-Token", "tok")
	rec = httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept with token: want 200, got %d", rec.Code)
	}
}

func TestToolsDriftAcceptBadBody(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/tools/accept", strings.NewReader(`not json`))
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("malformed accept body: want 400, got %d", rec.Code)
	}
	if toolsStatus(t, px)["pending_reapprove"] != false {
		t.Fatal("malformed accept must not set pending")
	}
}

func TestToolsDriftEstablishBeforePending(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.SetToolsReapprovePending("tester")
	postList(t, px)
	if n := countEvents(t, px, "tools_baseline", "establish"); n != 1 {
		t.Fatalf("first list with pending accept should establish, got %d", n)
	}
	if n := countEvents(t, px, "tools_baseline", "reapprove"); n != 0 {
		t.Fatalf("first list must not witness a reapproval, got %d", n)
	}
	if toolsStatus(t, px)["pending_reapprove"] != false {
		t.Fatal("establishment should consume the pending flag")
	}
}

func TestToolsDriftReapproveActor(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	px.SetToolsReapprovePending("tester")
	postList(t, px)
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Kind == "tools_baseline" && e.Decision == "reapprove" {
			if e.Actor != "tester" {
				t.Fatalf("reapprove actor should be tester, got %q", e.Actor)
			}
			return
		}
	}
	t.Fatal("no reapprove event found")
}

func TestToolsDriftEventArgs(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	baselineHash := ""
	if b, ok := toolsStatus(t, px)["baseline"].(map[string]any); ok {
		baselineHash, _ = b["hash"].(string)
	}
	stub.set([]listTool{{Name: "echo"}, {Name: "evil"}})
	postList(t, px)
	events, err := px.Ledger().Events()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if e.Kind == "tools_drift" && e.Decision == "drift" {
			var args map[string]any
			if err := json.Unmarshal(e.Args, &args); err != nil {
				t.Fatal(err)
			}
			added, _ := args["added"].([]any)
			if len(added) != 1 || added[0] != "evil" {
				t.Fatalf("drift args should list evil as added, got %v", args)
			}
			if args["baseline_hash"] != baselineHash {
				t.Fatalf("drift args should carry the baseline hash, got %v", args)
			}
			return
		}
	}
	t.Fatal("no drift event found")
}

func TestToolsDriftConcurrentLists(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo"}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	surfA, _, ok := parseToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}`))
	if !ok {
		t.Fatal("surface A should parse")
	}
	surfB, _, ok := parseToolsList([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"b"}]}}`))
	if !ok {
		t.Fatal("surface B should parse")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = px.applyToolsList(surfA, "gateway") }()
		go func() { defer wg.Done(); _ = px.applyToolsList(surfB, "gateway") }()
	}
	wg.Wait()
	final := ""
	if b, ok := toolsStatus(t, px)["baseline"].(map[string]any); ok {
		final, _ = b["hash"].(string)
	}
	if final != surfA.Hash && final != surfB.Hash {
		t.Fatalf("final baseline should be one of the raced surfaces, got %q", final)
	}
}

func TestToolsDriftBrokerHashAgreement(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, "version: 1\ncredentials:\n  - name: upstream-key\n    header: X-Upstream-Key\n    env: LEDGERLINE_TEST_BROKER_KEY\n")
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo", Description: "needs " + testSecret}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	px.SetBroker(b)
	if err := px.ProbeToolsBaseline(); err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	if n := countEvents(t, px, "tools_drift", "drift"); n != 0 {
		t.Fatalf("probe and passthrough must hash the same redacted surface, got %d drift events", n)
	}
}

func TestToolsDriftCorruptBaselineRow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "corrupt.db")
	store, err := ledger.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tools_baseline (id, tools_json, hash, created_at, updated_at) VALUES (1, 'not json', 'x', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store2, err := ledger.OpenSQLite(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New("http://localhost:1", store2, policy.New(nil, nil)); err == nil {
		t.Fatal("corrupt baseline row should fail proxy construction")
	}
}

func TestToolsDriftMultiLineSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"tools\":[{\"name\":\"echo\"}]}}\n\n")
	}))
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	if toolsStatus(t, px)["baseline"] == nil {
		t.Fatal("SSE payload split across data lines should establish a baseline")
	}
}

func TestToolsDriftKeyOrderNoDrift(t *testing.T) {
	stub := &mutableToolsStub{tools: []listTool{{Name: "echo", InputSchema: json.RawMessage(`{"type":"object","properties":{"b":{"type":"string"},"a":{"type":"string"}}}`)}}}
	srv := httptest.NewServer(stub)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	postList(t, px)
	stub.set([]listTool{{Name: "echo", InputSchema: json.RawMessage(`{"properties":{"a":{"type":"string"},"b":{"type":"string"}},"type":"object"}`)}})
	postList(t, px)
	if n := countEvents(t, px, "tools_drift", "drift"); n != 0 {
		t.Fatalf("same schema with reordered keys should not drift, got %d drift events", n)
	}
}
