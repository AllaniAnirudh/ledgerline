package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// countingPeer serves one mutable peer chain and counts what
// the gateway pulls. Requests counts every /v1/events hit.
// Served counts the events sent in all answers. The chain is
// read under a mutex, so the test can grow or tamper it
// between polls.
type countingPeer struct {
	mu       sync.Mutex
	chain    []ledger.Event
	requests atomic.Int32
	served   atomic.Int32
}

func (cp *countingPeer) serve(w http.ResponseWriter, r *http.Request) {
	cp.requests.Add(1)
	q := r.URL.Query()
	limit := 100
	if v := q.Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	offset := 0
	if v := q.Get("offset"); v != "" {
		offset, _ = strconv.Atoi(v)
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	total := len(cp.chain)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	out := cp.chain[offset:end]
	if out == nil {
		out = []ledger.Event{}
	}
	cp.served.Add(int32(len(out)))
	writeJSON(w, map[string]any{"events": out, "total": total, "limit": limit, "offset": offset})
}

// appendTools appends one hash-chained event per tool name to
// the peer chain. The ledger keeps the chain valid as it
// grows, so a later poll sees a longer verified chain.
func (cp *countingPeer) appendTools(t *testing.T, l *ledger.Ledger, tools ...string) {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, tool := range tools {
		e, err := l.Append("peer-session", "tool_call", tool, nil, "allow", "peer-agent")
		if err != nil {
			t.Fatal(err)
		}
		cp.chain = append(cp.chain, e)
	}
}

// tamperLast rewrites the tool name of the last chain event.
// The stored hash stays old, so the chain no longer verifies.
// It returns the old tool name, so the test can restore it.
func (cp *countingPeer) tamperLast(t *testing.T, tool string) string {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.chain) == 0 {
		t.Fatal("no events to tamper")
	}
	old := cp.chain[len(cp.chain)-1].Tool
	cp.chain[len(cp.chain)-1].Tool = tool
	return old
}

// tamperFirst rewrites the tool name of the first chain
// event. It returns the old tool name, so the test can
// restore it.
func (cp *countingPeer) tamperFirst(t *testing.T, tool string) string {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.chain) == 0 {
		t.Fatal("no events to tamper")
	}
	old := cp.chain[0].Tool
	cp.chain[0].Tool = tool
	return old
}

// restoreLast puts the old tool name back on the last chain
// event. The chain verifies again after the restore.
func (cp *countingPeer) restoreLast(t *testing.T, tool string) {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.chain[len(cp.chain)-1].Tool = tool
}

// restoreFirst puts the old tool name back on the first chain
// event. The chain verifies again after the restore.
func (cp *countingPeer) restoreFirst(t *testing.T, tool string) {
	t.Helper()
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.chain[0].Tool = tool
}

// mergedCacheResp is the merged answer shape the cache tests
// decode. It carries the three peer cause lists.
type mergedCacheResp struct {
	Events      []gatewayEvent `json:"events"`
	Total       int            `json:"total"`
	Unreachable []string       `json:"unreachable"`
	Unverified  []string       `json:"unverified"`
	Skipped     []string       `json:"skipped"`
}

func getMerged(t *testing.T, px *Proxy, path string) (int, mergedCacheResp) {
	t.Helper()
	code, raw := getAPI(t, px, path)
	var r mergedCacheResp
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return code, r
}

func TestPeerChainCacheSecondPollSkipsFullPull(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	cp := &countingPeer{}
	peerLedger := ledger.New()
	tools := make([]string, 0, 1200)
	for i := 0; i < 1200; i++ {
		tools = append(tools, fmt.Sprintf("tool-%04d", i))
	}
	cp.appendTools(t, peerLedger, tools...)
	srv := httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "big", URL: srv.URL}})

	// First poll pulls the full chain: one probe plus three
	// 500-event pages. It serves the probe event plus all
	// 1200 chain events. The merge caps one peer at 500
	// rows, so the merged total is 500, the newest 500.
	code, r := getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("first poll: want 200, got %d", code)
	}
	if r.Total != 500 {
		t.Fatalf("first poll total = %d, want 500 (newest 500 of 1200)", r.Total)
	}
	if len(r.Unreachable) != 0 || len(r.Unverified) != 0 {
		t.Fatalf("first poll lists: unreachable %v unverified %v, want none", r.Unreachable, r.Unverified)
	}
	if cp.requests.Load() != 4 {
		t.Fatalf("first poll requests = %d, want 4 (probe plus 3 pages)", cp.requests.Load())
	}
	if cp.served.Load() != 1201 {
		t.Fatalf("first poll served = %d, want 1201 (probe plus chain)", cp.served.Load())
	}

	// Second poll must not re-fetch the full chain. It makes
	// only the probe and the last-event check, and serves
	// only those two events. The merged total stays 500.
	reqBefore, servedBefore := cp.requests.Load(), cp.served.Load()
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("second poll: want 200, got %d", code)
	}
	if r.Total != 500 {
		t.Fatalf("second poll total = %d, want 500", r.Total)
	}
	if len(r.Unreachable) != 0 || len(r.Unverified) != 0 {
		t.Fatalf("second poll lists: unreachable %v unverified %v, want none", r.Unreachable, r.Unverified)
	}
	if d := cp.requests.Load() - reqBefore; d != 2 {
		t.Fatalf("second poll requests = %d, want 2 (probe plus last event)", d)
	}
	if d := cp.served.Load() - servedBefore; d != 2 {
		t.Fatalf("second poll served = %d, want 2 (probe plus last event)", d)
	}

	// The peers table uses the same cache. A peers call
	// also makes only the probe and the last-event check.
	reqBefore, servedBefore = cp.requests.Load(), cp.served.Load()
	code, raw := getAPI(t, px, "/v1/peers")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/peers: want 200, got %d", code)
	}
	var rows []peerStatus
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	var big peerStatus
	for _, row := range rows {
		if row.Name == "big" {
			big = row
		}
	}
	if !big.Reachable || !big.ChainOK || big.EventCount != 1200 {
		t.Fatalf("big row: want reachable chain ok count 1200, got %+v", big)
	}
	if d := cp.requests.Load() - reqBefore; d != 2 {
		t.Fatalf("peers call requests = %d, want 2 (probe plus last event)", d)
	}
	if d := cp.served.Load() - servedBefore; d != 2 {
		t.Fatalf("peers call served = %d, want 2 (probe plus last event)", d)
	}
}

func TestPeerChainCacheGrowsBySuffixOnly(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	cp := &countingPeer{}
	peerLedger := ledger.New()
	cp.appendTools(t, peerLedger, "tool-00", "tool-01", "tool-02", "tool-03", "tool-04", "tool-05", "tool-06", "tool-07", "tool-08", "tool-09")
	srv := httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "grow", URL: srv.URL}})

	code, r := getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK || r.Total != 10 {
		t.Fatalf("first poll: want 200 and total 10, got %d and %+v", code, r)
	}
	if cp.requests.Load() != 2 {
		t.Fatalf("first poll requests = %d, want 2 (probe plus page)", cp.requests.Load())
	}

	// The chain grows by two events. The next poll fetches
	// only the probe and the two new events.
	cp.appendTools(t, peerLedger, "tool-10", "tool-11")
	reqBefore, servedBefore := cp.requests.Load(), cp.served.Load()
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("growth poll: want 200, got %d", code)
	}
	if r.Total != 12 {
		t.Fatalf("growth poll total = %d, want 12", r.Total)
	}
	if d := cp.requests.Load() - reqBefore; d != 2 {
		t.Fatalf("growth poll requests = %d, want 2 (probe plus suffix)", d)
	}
	if d := cp.served.Load() - servedBefore; d != 3 {
		t.Fatalf("growth poll served = %d, want 3 (probe plus 2 new events)", d)
	}
	seen := map[string]bool{}
	for _, e := range r.Events {
		seen[e.Tool] = true
	}
	if !seen["tool-10"] || !seen["tool-11"] {
		t.Fatalf("growth poll rows miss the new events: %+v", r.Events)
	}

	// The grown chain is cached now. The next poll is back
	// to the probe plus the last-event check.
	reqBefore, servedBefore = cp.requests.Load(), cp.served.Load()
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK || r.Total != 12 {
		t.Fatalf("third poll: want 200 and total 12, got %d and %+v", code, r)
	}
	if d := cp.requests.Load() - reqBefore; d != 2 {
		t.Fatalf("third poll requests = %d, want 2 (probe plus last event)", d)
	}
	if d := cp.served.Load() - servedBefore; d != 2 {
		t.Fatalf("third poll served = %d, want 2 (probe plus last event)", d)
	}
}

func TestPeerChainCacheTamperDropsCache(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	cp := &countingPeer{}
	peerLedger := ledger.New()
	cp.appendTools(t, peerLedger, "tool-0", "tool-1", "tool-2", "tool-3", "tool-4")
	srv := httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "vic", URL: srv.URL}})

	code, r := getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK || r.Total != 5 {
		t.Fatalf("first poll: want 200 and total 5, got %d and %+v", code, r)
	}

	// Tamper the last event. The next poll must report the
	// peer unverified, not unreachable, and must have run a
	// full pull: probe, last-event check, then one page.
	oldLast := cp.tamperLast(t, "tampered_tool")
	reqBefore := cp.requests.Load()
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("tamper poll: want 200, got %d", code)
	}
	if r.Total != 0 {
		t.Fatalf("tamper poll total = %d, want 0: no peer event may merge", r.Total)
	}
	if len(r.Unreachable) != 0 {
		t.Fatalf("tamper poll unreachable = %v, want none: the peer answered", r.Unreachable)
	}
	if len(r.Unverified) != 1 || r.Unverified[0] != "vic" {
		t.Fatalf("tamper poll unverified = %v, want [vic]", r.Unverified)
	}
	if d := cp.requests.Load() - reqBefore; d != 3 {
		t.Fatalf("tamper poll requests = %d, want 3 (probe, last event, full page)", d)
	}
	code, raw := getAPI(t, px, "/v1/events?gateway=vic")
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("direct tampered pull: want 422, got %d (%s)", code, raw)
	}

	// Restore the last event. The cache was dropped, so the
	// next poll pulls the full chain again and verifies it.
	cp.restoreLast(t, oldLast)
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK || r.Total != 5 {
		t.Fatalf("restore poll: want 200 and total 5, got %d and %+v", code, r)
	}
	if len(r.Unverified) != 0 || len(r.Unreachable) != 0 {
		t.Fatalf("restore poll lists: unverified %v unreachable %v, want none", r.Unverified, r.Unreachable)
	}

	// Tamper the first event. The probe already fetches it,
	// so the next poll must also report the peer unverified.
	oldFirst := cp.tamperFirst(t, "tampered_tool")
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK {
		t.Fatalf("first-event tamper poll: want 200, got %d", code)
	}
	if r.Total != 0 {
		t.Fatalf("first-event tamper poll total = %d, want 0", r.Total)
	}
	if len(r.Unverified) != 1 || r.Unverified[0] != "vic" {
		t.Fatalf("first-event tamper poll unverified = %v, want [vic]", r.Unverified)
	}

	// Restore the first event. The chain verifies again.
	cp.restoreFirst(t, oldFirst)
	code, r = getMerged(t, px, "/v1/events?limit=500")
	if code != http.StatusOK || r.Total != 5 {
		t.Fatalf("second restore poll: want 200 and total 5, got %d and %+v", code, r)
	}
	if len(r.Unverified) != 0 || len(r.Unreachable) != 0 {
		t.Fatalf("second restore poll lists: unverified %v unreachable %v, want none", r.Unverified, r.Unreachable)
	}
}

func TestPeerChainCacheOverLimitNeverCached(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		writeJSON(w, map[string]any{"events": []ledger.Event{}, "total": 5001, "limit": 1, "offset": 0})
	}))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "big", URL: srv.URL}})

	// An over-limit chain is unverified on every call. The
	// probe runs each time. Nothing is cached as verified.
	for i := 0; i < 2; i++ {
		code, raw := getAPI(t, px, "/v1/peers")
		if code != http.StatusOK {
			t.Fatalf("call %d: want 200, got %d", i, code)
		}
		var rows []peerStatus
		if err := json.Unmarshal(raw, &rows); err != nil {
			t.Fatal(err)
		}
		var big peerStatus
		for _, row := range rows {
			if row.Name == "big" {
				big = row
			}
		}
		if !big.Reachable || big.ChainOK {
			t.Fatalf("call %d: want reachable but unverified, got %+v", i, big)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("peer hits = %d, want 2 (one probe per call, never cached)", hits.Load())
	}
}

func TestPeerChainCacheConcurrentPolls(t *testing.T) {
	px, _ := testProxy(t)
	px.SetAPIToken("s3cret")
	cp := &countingPeer{}
	peerLedger := ledger.New()
	tools := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		tools = append(tools, fmt.Sprintf("tool-%02d", i))
	}
	cp.appendTools(t, peerLedger, tools...)
	srv := httptest.NewServer(http.HandlerFunc(cp.serve))
	t.Cleanup(srv.Close)
	px.SetPeers([]PeerConfig{{Name: "par", URL: srv.URL}})

	// Two waves of parallel polls hit the cache at once.
	// The first wave pulls and caches. The second wave
	// reads the cache. Every poll must see all 50 events.
	for wave := 0; wave < 2; wave++ {
		var wg sync.WaitGroup
		errs := make(chan string, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				code, r := getMerged(t, px, "/v1/events?limit=500")
				if code != http.StatusOK {
					errs <- fmt.Sprintf("wave %d: want 200, got %d", wave, code)
					return
				}
				if r.Total != 50 {
					errs <- fmt.Sprintf("wave %d: total = %d, want 50", wave, r.Total)
				}
			}()
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatal(e)
		}
	}
}
