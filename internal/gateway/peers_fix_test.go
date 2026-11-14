package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// chainEvents builds a real hash-chained peer chain. Each tool
// name becomes one event, in order. The chain verifies.
func chainEvents(t *testing.T, tools ...string) []ledger.Event {
	t.Helper()
	l := ledger.New()
	out := make([]ledger.Event, 0, len(tools))
	for _, tool := range tools {
		e, err := l.Append("peer-session", "tool_call", tool, nil, "allow", "peer-agent")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// writePagedEvents serves one peer chain page. It honours the
// limit and offset query params, like GET /v1/events does.
func writePagedEvents(w http.ResponseWriter, r *http.Request, events []ledger.Event) {
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}
	total := len(events)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := events[offset:end]
	if out == nil {
		out = []ledger.Event{}
	}
	writeJSON(w, map[string]any{"events": out, "total": total, "limit": limit, "offset": offset})
}

func TestFabricatedPeerNeverChainOK(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	var verifyHits atomic.Int32
	// The peer claims its chain is fine and serves one invented
	// event. The event has no hash, so no real chain holds it.
	invented := peerEvent(99, time.Now().UTC(), "evil_tool", "allow")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/verify":
			verifyHits.Add(1)
			writeJSON(w, map[string]any{"ok": true, "error": ""})
		case "/v1/events":
			writeJSON(w, map[string]any{"events": []ledger.Event{invented}, "total": 1, "limit": 100, "offset": 0})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "fab", URL: srv.URL}})

	code, raw := getAPI(t, px, "/v1/peers")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/peers: want 200, got %d (%s)", code, raw)
	}
	var rows []peerStatus
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	var fab peerStatus
	for _, r := range rows {
		if r.Name == "fab" {
			fab = r
		}
	}
	if !fab.Reachable || fab.ChainOK || !strings.Contains(fab.ChainError, "hash mismatch") {
		t.Fatalf("fab row: want reachable with a local hash failure, got %+v", fab)
	}
	if fab.EventCount != 1 {
		t.Fatalf("fab event count = %d, want 1", fab.EventCount)
	}
	if verifyHits.Load() != 0 {
		t.Fatalf("peer /v1/verify was called %d times, want 0: its answer is never trusted", verifyHits.Load())
	}

	// The invented event must not reach the merged timeline.
	type mergedResp struct {
		Events      []gatewayEvent `json:"events"`
		Unreachable []string       `json:"unreachable"`
	}
	code, raw = getAPI(t, px, "/v1/events")
	if code != http.StatusOK {
		t.Fatalf("merged: want 200, got %d", code)
	}
	var m mergedResp
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Events {
		if e.Tool == "evil_tool" {
			t.Fatalf("invented peer event reached the merged timeline: %+v", e)
		}
	}
	found := false
	for _, n := range m.Unreachable {
		if n == "fab" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unreachable = %v, want it to name fab", m.Unreachable)
	}

	// A direct pull of the fabricated peer must refuse too.
	code, _ = getAPI(t, px, "/v1/events?gateway=fab")
	if code != http.StatusBadGateway {
		t.Fatalf("direct fabricated pull: want 502, got %d", code)
	}
}

func TestPeerChainTooLargeMarkedUnverified(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	var eventsHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventsHits.Add(1)
		writeJSON(w, map[string]any{"events": []ledger.Event{}, "total": 5001, "limit": 1, "offset": 0})
	}))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "big", URL: srv.URL}})

	code, raw := getAPI(t, px, "/v1/peers")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/peers: want 200, got %d (%s)", code, raw)
	}
	var rows []peerStatus
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	var big peerStatus
	for _, r := range rows {
		if r.Name == "big" {
			big = r
		}
	}
	if !big.Reachable || big.ChainOK || !strings.Contains(big.ChainError, "over the 5000-event") {
		t.Fatalf("big row: want reachable but unverified over the limit, got %+v", big)
	}
	if big.EventCount != 5001 {
		t.Fatalf("big event count = %d, want 5001", big.EventCount)
	}
	if eventsHits.Load() != 1 {
		t.Fatalf("peer events hits = %d, want 1 probe only", eventsHits.Load())
	}
}

func TestPeerFilterQuerySetsLocalGateway(t *testing.T) {
	q := peerFilterQuery(url.Values{"session": {"s1"}, "limit": {"10"}, "offset": {"5"}})
	if q.Get("gateway") != "local" {
		t.Fatalf("gateway = %q, want local", q.Get("gateway"))
	}
	if q.Get("session") != "s1" {
		t.Fatalf("session = %q, want s1", q.Get("session"))
	}
	if q.Get("limit") != "" || q.Get("offset") != "" {
		t.Fatalf("peer query must not carry paging, got limit %q offset %q", q.Get("limit"), q.Get("offset"))
	}
}

func TestForeignPeerEventsNeverMerged(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	own := chainEvents(t, "own_tool")
	foreign := peerEvent(0, time.Now().UTC(), "foreign_tool", "allow")
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Query().Get("gateway"))
		mu.Unlock()
		if r.URL.Query().Get("gateway") == "local" {
			writePagedEvents(w, r, own)
			return
		}
		// A peer that merges its own peers returns foreign
		// events when the caller does not ask for local only.
		writePagedEvents(w, r, append(append([]ledger.Event{}, own...), foreign))
	}))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "mix", URL: srv.URL}})

	code, raw := getAPI(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("merged: want 200, got %d", code)
	}
	var m struct {
		Events []gatewayEvent `json:"events"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Events {
		if e.Tool == "foreign_tool" {
			t.Fatalf("foreign peer event reached the merged timeline: %+v", e)
		}
	}
	foundOwn := false
	for _, e := range m.Events {
		if e.Tool == "own_tool" && e.Gateway == "mix" {
			foundOwn = true
		}
	}
	if !foundOwn {
		t.Fatalf("merged rows must carry the peer own event, got %+v", m.Events)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the peer was never pulled")
	}
	for _, g := range seen {
		if g != "local" {
			t.Fatalf("peer pull asked gateway %q, want local on every pull", g)
		}
	}
}

func TestMutualPeerCycleTerminates(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	postTool(t, px, "read_file")
	var gatewaySrv *httptest.Server
	var mu sync.Mutex
	peerHits, callbacks := 0, 0
	peerChain := chainEvents(t, "peer_tool")
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		peerHits++
		first := peerHits == 1
		mu.Unlock()
		if first {
			// The peer pulls its own peer back: us. It
			// forwards the visited header it received.
			mu.Lock()
			callbacks++
			mu.Unlock()
			client := &http.Client{Timeout: 5 * time.Second}
			req, err := http.NewRequest(http.MethodGet, gatewaySrv.URL+"/v1/events", nil)
			if err != nil {
				t.Error(err)
			} else {
				req.Header.Set("X-Ledgerline-Token", "s3cret")
				req.Header.Set(peerVisitedHeader, r.Header.Get(peerVisitedHeader))
				resp, err := client.Do(req)
				if err != nil {
					t.Error(err)
				} else {
					_, _ = io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}
		}
		writePagedEvents(w, r, peerChain)
	}))
	t.Cleanup(peer.Close)
	gatewaySrv = httptest.NewServer(px)
	t.Cleanup(gatewaySrv.Close)
	px.SetPeers([]PeerConfig{{Name: "cyc", URL: peer.URL}})

	start := time.Now()
	code, raw := getAPI(t, px, "/v1/events?limit=500")
	elapsed := time.Since(start)
	if code != http.StatusOK {
		t.Fatalf("merged: want 200, got %d (%s)", code, raw)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("cycle pull took %v, want under 2s", elapsed)
	}
	mu.Lock()
	hits, cbs := peerHits, callbacks
	mu.Unlock()
	if hits != 2 || cbs != 1 {
		t.Fatalf("peer hits = %d, callbacks = %d, want 2 and 1", hits, cbs)
	}
	var m struct {
		Events []gatewayEvent `json:"events"`
		Total  int            `json:"total"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	// Local read_file writes 2 events. The peer adds 1.
	if m.Total != 3 {
		t.Fatalf("merged total = %d, want 3", m.Total)
	}
}

func TestPeerCapKeepsNewestAndFlagsTruncated(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	tools := make([]string, 0, 503)
	for i := 0; i < 503; i++ {
		tools = append(tools, fmt.Sprintf("tool-%03d", i))
	}
	srv := fakePeer(t, "", true, "", chainEvents(t, tools...))
	px.SetPeers([]PeerConfig{{Name: "cap", URL: srv.URL}})

	type resp struct {
		Events     []gatewayEvent `json:"events"`
		Total      int            `json:"total"`
		Truncated  []string       `json:"truncated"`
		PeerTotals map[string]int `json:"peer_totals"`
	}
	get := func(path string) resp {
		t.Helper()
		code, raw := getAPI(t, px, path)
		if code != http.StatusOK {
			t.Fatalf("GET %s: want 200, got %d (%s)", path, code, raw)
		}
		var r resp
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	r0 := get("/v1/events?limit=500&offset=0")
	r1 := get("/v1/events?limit=500&offset=500")
	rows := append(append([]gatewayEvent{}, r0.Events...), r1.Events...)
	if r0.Total != 500 || len(rows) != 500 {
		t.Fatalf("merged total = %d with %d rows, want 500 and 500", r0.Total, len(rows))
	}
	minSeq, maxSeq := uint64(1<<64-1), uint64(0)
	for _, e := range rows {
		if e.Gateway != "cap" {
			t.Fatalf("merged row has gateway %q, want cap", e.Gateway)
		}
		if e.Seq < minSeq {
			minSeq = e.Seq
		}
		if e.Seq > maxSeq {
			maxSeq = e.Seq
		}
	}
	if minSeq != 3 || maxSeq != 502 {
		t.Fatalf("peer seq range = %d..%d, want 3..502 (newest 500 of 503)", minSeq, maxSeq)
	}
	if len(r0.Truncated) != 1 || r0.Truncated[0] != "cap" {
		t.Fatalf("truncated = %v, want [cap]", r0.Truncated)
	}
	if r0.PeerTotals["cap"] != 503 {
		t.Fatalf("peer_totals = %v, want cap 503", r0.PeerTotals)
	}
}

func TestPeerResponseSizeCap(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, (8<<20)+1))
	}))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "big", URL: srv.URL}})

	code, raw := getAPI(t, px, "/v1/peers")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/peers: want 200, got %d (%s)", code, raw)
	}
	var rows []peerStatus
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	var big peerStatus
	for _, r := range rows {
		if r.Name == "big" {
			big = r
		}
	}
	if big.Reachable || !strings.Contains(big.Error, "over the") || !strings.Contains(big.Error, "byte") {
		t.Fatalf("big row: want unreachable over the byte limit, got %+v", big)
	}
}

func TestLoadPeersFileRefusesRemotePlainHTTP(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	bad := write("bad.json", `[{"name":"a","url":"http://10.0.0.2:8080","token":"tok"}]`)
	if _, err := LoadPeersFile(bad); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("remote plain http peer must fail naming https, got err %v", err)
	}
	ok := []string{
		`[{"name":"a","url":"https://10.0.0.2:8080","token":"tok"}]`,
		`[{"name":"a","url":"http://localhost:9001","token":"tok"}]`,
		`[{"name":"a","url":"http://127.0.0.1:9001","token":"tok"}]`,
		`[{"name":"a","url":"http://[::1]:9001","token":"tok"}]`,
	}
	for i, body := range ok {
		if _, err := LoadPeersFile(write(fmt.Sprintf("ok%d.json", i), body)); err != nil {
			t.Fatalf("case %d must load, got %v", i, err)
		}
	}
}
