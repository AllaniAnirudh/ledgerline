// Peer gateways feed the dashboard pull. Each peer keeps its
// own SQLite chain. This gateway pulls the peer chain and
// verifies it here, with ledger.VerifyEvents. It never trusts
// the peer own /v1/verify answer. A verified chain is cached
// per peer. A later poll re-checks the chain ends and fetches
// only the new suffix. A peer that does not answer shows as
// down. It is never silent. The merged timeline sorts by
// timestamp. It never claims one global chain order.
package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// peerTimeout bounds one peer request. A slow peer must not
// stall the dashboard. Five seconds is the cap.
const peerTimeout = 5 * time.Second

// peerEventCap bounds one peer pull in a merged timeline. A
// peer with more filtered events than this contributes its
// newest rows first. The merge names capped peers in the
// truncated list. The cap keeps one merge bounded.
const peerEventCap = 500

// peerVerifyMaxEvents bounds local chain verification. A peer
// with more events than this is marked unverified, never
// chain-ok. The pull pages 500 events at a time, so this is
// at most 10 peer requests.
const peerVerifyMaxEvents = 5000

// maxPeerResponseBytes bounds one peer response body. A peer
// that answers with more is refused. The cap stops a bad peer
// from growing gateway memory without bound.
const maxPeerResponseBytes = 8 << 20

// peerVisitedHeader carries the peer urls already pulled in
// this pull chain. A gateway refuses to pull a peer whose url
// is already listed. Mutual peers cannot recurse.
const peerVisitedHeader = "X-Ledgerline-Visited"

// errPeerChainInvalid marks a peer chain failure. The peer
// answered, but its chain did not verify here, or it is too
// large to pull. Callers treat this as reachable but not
// chain-ok. Other errors mean the peer did not answer.
var errPeerChainInvalid = errors.New("peer chain did not verify locally")

// cachedPeerChain is one verified peer chain. The chain was
// verified in this process. Entries are never mutated after
// they are stored. An update replaces the map value. Total is
// the chain length. LastSeq and LastHash describe the last
// event. They are the watermark for the next poll.
type cachedPeerChain struct {
	chain    []ledger.Event
	total    int
	lastSeq  uint64
	lastHash string
}

// peerChainCache holds the verified chains for one gateway.
// The mutex guards the map. No lock is ever held across a
// network call. Callers copy an entry out, then release the
// lock before they pull.
type peerChainCache struct {
	mu    sync.Mutex
	byURL map[string]*cachedPeerChain
}

// peerChainCaches holds one cache per gateway. The Proxy type
// lives in proxy.go, outside this lane, so the cache cannot
// sit on the struct. The map is keyed by gateway pointer.
// Each gateway gets its own cache. Entries are small. The
// gateway count in one process stays low.
var peerChainCaches sync.Map // *Proxy -> *peerChainCache

// peerCache returns the verified-chain cache for this
// gateway. It creates the cache on first use.
func (px *Proxy) peerCache() *peerChainCache {
	c, _ := peerChainCaches.LoadOrStore(px, &peerChainCache{byURL: map[string]*cachedPeerChain{}})
	return c.(*peerChainCache)
}

// cachedPeerChainFor returns the cached chain for one peer
// url, when one exists. The entry is never mutated after it
// is stored, so the caller may read it without the lock.
func (px *Proxy) cachedPeerChainFor(peerURL string) (*cachedPeerChain, bool) {
	c := px.peerCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byURL[peerURL]
	return e, ok
}

// storePeerChain caches one verified chain. The chain is
// copied, so later caller use cannot mutate the cache. The
// stored total must equal the stored chain length.
func (px *Proxy) storePeerChain(peerURL string, chain []ledger.Event, total int) {
	cp := make([]ledger.Event, len(chain))
	copy(cp, chain)
	e := &cachedPeerChain{chain: cp, total: total}
	if len(cp) > 0 {
		e.lastSeq = cp[len(cp)-1].Seq
		e.lastHash = cp[len(cp)-1].Hash
	}
	c := px.peerCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byURL[peerURL] = e
}

// dropPeerChain removes the cached chain for one peer url.
// A dropped chain is never served again. The next poll pulls
// it from scratch.
func (px *Proxy) dropPeerChain(peerURL string) {
	c := px.peerCache()
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byURL, peerURL)
}

// sameEvent reports whether two events carry the same fields.
// The watermark check compares the fetched first and last
// events with the cached ends. Any field change counts as a
// mismatch, even when the stored hash field is unchanged.
func sameEvent(a, b ledger.Event) bool {
	return a.Seq == b.Seq &&
		a.Timestamp.Equal(b.Timestamp) &&
		a.SessionID == b.SessionID &&
		a.Kind == b.Kind &&
		a.Tool == b.Tool &&
		string(a.Args) == string(b.Args) &&
		a.Decision == b.Decision &&
		a.Actor == b.Actor &&
		a.Mode == b.Mode &&
		a.DecisionID == b.DecisionID &&
		a.PolicyHash == b.PolicyHash &&
		a.AgentID == b.AgentID &&
		a.PrevHash == b.PrevHash &&
		a.Hash == b.Hash
}

// PeerConfig is one entry in the peer gateways file. The file
// holds tokens. Keep it readable only by the operator.
type PeerConfig struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Token string `json:"token"`
}

// LoadPeersFile reads the peer gateways file. The file must not
// be readable by group or others. A file with loose permission
// bits is refused. Names must be set, unique, and not "local".
// URLs must parse and use http or https. Plain http is refused
// except for loopback hosts. A control-plane token must never
// cross a plain http link to a remote host.
func LoadPeersFile(path string) ([]PeerConfig, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("peer gateways file %s must not be readable by group or others (mode %04o)", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var peers []PeerConfig
	if err := json.Unmarshal(b, &peers); err != nil {
		return nil, fmt.Errorf("peer gateways file: %w", err)
	}
	seen := map[string]bool{}
	for _, p := range peers {
		if p.Name == "" {
			return nil, fmt.Errorf("peer gateways file: a peer has no name")
		}
		if p.Name == "local" {
			return nil, fmt.Errorf("peer gateways file: peer name %q is reserved for the local gateway", p.Name)
		}
		if seen[p.Name] {
			return nil, fmt.Errorf("peer gateways file: duplicate peer name %q", p.Name)
		}
		seen[p.Name] = true
		if p.URL == "" {
			return nil, fmt.Errorf("peer gateways file: peer %q has no url", p.Name)
		}
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("peer gateways file: peer %q has a bad url %q", p.Name, p.URL)
		}
		if u.Scheme == "http" && !isLoopbackPeerURL(u) {
			return nil, fmt.Errorf("peer gateways file: peer %q url %q uses plain http to a non-loopback host; peer urls must use https except loopback hosts", p.Name, p.URL)
		}
	}
	if peers == nil {
		peers = []PeerConfig{}
	}
	return peers, nil
}

// isLoopbackPeerURL reports whether a peer url points at this
// host. Localhost names and loopback IPs count. All other
// hosts need https.
func isLoopbackPeerURL(u *url.URL) bool {
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// peerStatus is one row of GET /v1/peers. LastSync is set only
// when the peer answered. ChainError carries the verify failure
// text. Error carries the fetch failure text. A down peer has
// Reachable false and Error set.
type peerStatus struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	Reachable  bool   `json:"reachable"`
	LastSync   string `json:"last_sync,omitempty"`
	ChainOK    bool   `json:"chain_ok"`
	ChainError string `json:"chain_error,omitempty"`
	EventCount int    `json:"event_count"`
	Error      string `json:"error,omitempty"`
}

// visitedHeaderValue builds the visited header value. It lists
// the urls already pulled, plus the url about to be pulled.
// The list is sorted, so the header is stable.
func visitedHeaderValue(visited map[string]bool, add string) string {
	names := make([]string, 0, len(visited)+1)
	for v := range visited {
		names = append(names, v)
	}
	if add != "" {
		names = append(names, add)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// parseVisitedHeader reads the visited header off an incoming
// peer pull request. A missing header means an empty set.
func parseVisitedHeader(r *http.Request) map[string]bool {
	out := map[string]bool{}
	for _, v := range strings.Split(r.Header.Get(peerVisitedHeader), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out[v] = true
		}
	}
	return out
}

// fetchPeerEvents asks one peer for filtered events. Query
// params carry the caller filters. The answer is the peer
// events plus the peer total before paging. The response body
// is capped. A peer that answers with more is refused.
func (px *Proxy) fetchPeerEvents(p PeerConfig, q url.Values, visited map[string]bool) ([]ledger.Event, int, error) {
	u := p.URL + "/v1/events?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set(peerVisitedHeader, visitedHeaderValue(visited, p.URL))
	if p.Token != "" {
		req.Header.Set("X-Ledgerline-Token", p.Token)
	}
	resp, err := px.peerClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("events answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPeerResponseBytes+1))
	if err != nil {
		return nil, 0, fmt.Errorf("events answer did not read: %w", err)
	}
	if len(body) > maxPeerResponseBytes {
		return nil, 0, fmt.Errorf("events answer over the %d byte peer response limit", maxPeerResponseBytes)
	}
	var r eventsResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, 0, fmt.Errorf("events answer did not parse: %w", err)
	}
	return r.Events, r.Total, nil
}

// fetchVerifiedPeerChain pulls one peer chain and verifies
// it here. The pull asks for the peer own events only. It
// never reads the peer /v1/verify answer. A chain over the
// verify limit is refused without paging. A chain that fails
// the local check is refused with errPeerChainInvalid. A peer
// that does not answer returns a plain fetch error.
//
// A verified chain is cached per peer url. A later poll
// probes the total first. When the total is unchanged, the
// poll compares the fetched first and last events with the
// cached ends. When both ends match, the cached chain is
// served. No full pull runs. When the chain grew, the poll
// fetches only the new suffix and verifies the cached chain
// plus the suffix with ledger.VerifyEvents. The suffix fetch
// is network only. The hash check still runs in this process,
// because the ledger exposes no suffix-only verifier. On any
// watermark mismatch, the cache is dropped and the chain is
// pulled and verified from scratch. On any verification
// failure, the cache is dropped and the peer reports
// unverified. A chain over the limit is never cached as
// verified. A cached chain is served only after its ends were
// confirmed on this poll. A peer that rewrites middle history
// while keeping the length and both ends bit-identical is not
// caught by this check. That case needs a full pull.
func (px *Proxy) fetchVerifiedPeerChain(p PeerConfig, visited map[string]bool) ([]ledger.Event, int, error) {
	probe := url.Values{}
	probe.Set("gateway", "local")
	probe.Set("limit", "1")
	probe.Set("offset", "0")
	probeEvents, total, err := px.fetchPeerEvents(p, probe, visited)
	if err != nil {
		return nil, 0, err
	}
	if total > peerVerifyMaxEvents {
		px.dropPeerChain(p.URL)
		return nil, total, fmt.Errorf("peer chain has %d events, over the %d-event local verify limit: %w", total, peerVerifyMaxEvents, errPeerChainInvalid)
	}
	if total == 0 {
		px.storePeerChain(p.URL, nil, 0)
		return []ledger.Event{}, 0, nil
	}
	cached, haveCache := px.cachedPeerChainFor(p.URL)
	if haveCache && len(cached.chain) == cached.total {
		switch {
		case cached.total == total:
			// The length is unchanged. Check both ends.
			// The probe already fetched the first event.
			// Fetch the last event next.
			if len(probeEvents) == 1 && sameEvent(probeEvents[0], cached.chain[0]) {
				tip := url.Values{}
				tip.Set("gateway", "local")
				tip.Set("limit", "1")
				tip.Set("offset", strconv.Itoa(total-1))
				tipEvents, tipTotal, tipErr := px.fetchPeerEvents(p, tip, visited)
				if tipErr == nil {
					if tipTotal == total && len(tipEvents) == 1 && sameEvent(tipEvents[0], cached.chain[len(cached.chain)-1]) {
						out := make([]ledger.Event, len(cached.chain))
						copy(out, cached.chain)
						return out, total, nil
					}
					px.dropPeerChain(p.URL)
				}
				// A tip fetch error is a network failure,
				// not a chain failure. Keep the cache and
				// fall through to a full pull. The full
				// pull either refreshes the cache or
				// reports the fetch error.
			} else {
				px.dropPeerChain(p.URL)
			}
			return px.pullAndVerifyPeerChain(p, visited, total)
		case cached.total < total:
			// The chain grew. Fetch only the new suffix.
			suffix, err := px.fetchPeerSuffix(p, visited, cached.total, total)
			if err != nil {
				if errors.Is(err, errPeerChainInvalid) {
					px.dropPeerChain(p.URL)
				}
				return nil, total, err
			}
			full := make([]ledger.Event, 0, total)
			full = append(full, cached.chain...)
			full = append(full, suffix...)
			if err := ledger.VerifyEvents(full); err != nil {
				px.dropPeerChain(p.URL)
				return nil, total, fmt.Errorf("peer chain failed local verify (%v): %w", err, errPeerChainInvalid)
			}
			px.storePeerChain(p.URL, full, total)
			return full, total, nil
		default:
			// The chain shrank. A shorter chain is a
			// watermark mismatch. Drop the cache and pull
			// the chain from scratch.
			px.dropPeerChain(p.URL)
			return px.pullAndVerifyPeerChain(p, visited, total)
		}
	}
	if haveCache {
		px.dropPeerChain(p.URL)
	}
	return px.pullAndVerifyPeerChain(p, visited, total)
}

// pullAndVerifyPeerChain pulls one peer full chain and
// verifies it here. The pull pages through /v1/events. A page
// total that changes mid-pull refuses the chain. A short pull
// refuses the chain. A failed local check refuses the chain
// with errPeerChainInvalid. A verified chain is cached.
func (px *Proxy) pullAndVerifyPeerChain(p PeerConfig, visited map[string]bool, total int) ([]ledger.Event, int, error) {
	chain := make([]ledger.Event, 0, total)
	for offset := 0; offset < total; offset += peerEventCap {
		q := url.Values{}
		q.Set("gateway", "local")
		q.Set("limit", strconv.Itoa(peerEventCap))
		q.Set("offset", strconv.Itoa(offset))
		page, pageTotal, err := px.fetchPeerEvents(p, q, visited)
		if err != nil {
			return nil, total, err
		}
		if pageTotal != total {
			px.dropPeerChain(p.URL)
			return nil, total, fmt.Errorf("peer event total changed mid-pull (%d, was %d): %w", pageTotal, total, errPeerChainInvalid)
		}
		chain = append(chain, page...)
	}
	if len(chain) != total {
		px.dropPeerChain(p.URL)
		return nil, total, fmt.Errorf("peer chain pull short: got %d events, total %d: %w", len(chain), total, errPeerChainInvalid)
	}
	if err := ledger.VerifyEvents(chain); err != nil {
		px.dropPeerChain(p.URL)
		return nil, total, fmt.Errorf("peer chain failed local verify (%v): %w", err, errPeerChainInvalid)
	}
	px.storePeerChain(p.URL, chain, total)
	return chain, total, nil
}

// fetchPeerSuffix pulls only the events a cached chain does
// not hold yet, from offset from to the total. A page total
// that changes mid-pull refuses the suffix. A short suffix
// pull refuses the suffix. Both failures carry
// errPeerChainInvalid. A plain fetch error passes through.
func (px *Proxy) fetchPeerSuffix(p PeerConfig, visited map[string]bool, from, total int) ([]ledger.Event, error) {
	out := make([]ledger.Event, 0, total-from)
	for offset := from; offset < total; offset += peerEventCap {
		q := url.Values{}
		q.Set("gateway", "local")
		q.Set("limit", strconv.Itoa(peerEventCap))
		q.Set("offset", strconv.Itoa(offset))
		page, pageTotal, err := px.fetchPeerEvents(p, q, visited)
		if err != nil {
			return nil, err
		}
		if pageTotal != total {
			return nil, fmt.Errorf("peer event total changed mid-pull (%d, was %d): %w", pageTotal, total, errPeerChainInvalid)
		}
		out = append(out, page...)
	}
	if len(out) != total-from {
		return nil, fmt.Errorf("peer chain suffix pull short: got %d events, want %d: %w", len(out), total-from, errPeerChainInvalid)
	}
	return out, nil
}

// peerStatusFor builds one peer row. The chain is verified
// here, never by the peer. A verify failure still reports the
// peer as reachable, with ChainOK false. Only a failed request
// reports it as down.
func (px *Proxy) peerStatusFor(p PeerConfig) peerStatus {
	st := peerStatus{Name: p.Name, URL: p.URL}
	_, total, err := px.fetchVerifiedPeerChain(p, map[string]bool{})
	if err != nil {
		if errors.Is(err, errPeerChainInvalid) {
			st.Reachable = true
			st.LastSync = time.Now().UTC().Format(time.RFC3339Nano)
			st.ChainError = err.Error()
			st.EventCount = total
			return st
		}
		st.Error = err.Error()
		return st
	}
	st.Reachable = true
	st.LastSync = time.Now().UTC().Format(time.RFC3339Nano)
	st.ChainOK = true
	st.EventCount = total
	return st
}

// localPeerStatus builds the "local" row. The local gateway is
// always a peer. Its chain is verified in process.
func (px *Proxy) localPeerStatus() peerStatus {
	st := peerStatus{Name: "local", Reachable: true, LastSync: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := px.ledger.Verify(); err != nil {
		st.ChainError = err.Error()
		return st
	}
	st.ChainOK = true
	events, err := px.ledger.Events()
	if err != nil {
		st.Error = "ledger read failed"
		return st
	}
	st.EventCount = len(events)
	return st
}

// servePeers answers GET /v1/peers. It pulls every peer on
// demand. Peer pulls run in parallel. Rows stay in config
// order, local first.
func (px *Proxy) servePeers(w http.ResponseWriter, r *http.Request) {
	px.peersMu.RLock()
	peers := px.peers
	px.peersMu.RUnlock()
	out := make([]peerStatus, len(peers)+1)
	out[0] = px.localPeerStatus()
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p PeerConfig) {
			defer wg.Done()
			out[i+1] = px.peerStatusFor(p)
		}(i, p)
	}
	wg.Wait()
	writeJSON(w, out)
}

// gatewayEvent is one merged timeline row. It is a ledger event
// plus the name of the gateway that witnessed it.
type gatewayEvent struct {
	ledger.Event
	Gateway string `json:"gateway"`
}

// mergedEventsResponse is the shape of a merged GET /v1/events
// answer. MergedBy is set only when the timeline merges more
// than one source. Unreachable names peers that did not answer
// during the merge. Unverified names peers that answered but
// whose chain did not verify here. Skipped names peers that
// were already visited in this pull chain. Their events are
// absent, not silent. The three lists never overlap. A peer
// lands in exactly one list. Truncated names peers whose
// filtered events passed the per peer cap, so only their
// newest rows are present. PeerTotals holds each pulled peer
// filtered total before the cap.
type mergedEventsResponse struct {
	Events      []gatewayEvent `json:"events"`
	Total       int            `json:"total"`
	Limit       int            `json:"limit"`
	Offset      int            `json:"offset"`
	MergedBy    string         `json:"merged_by,omitempty"`
	Unreachable []string       `json:"unreachable,omitempty"`
	Unverified  []string       `json:"unverified,omitempty"`
	Skipped     []string       `json:"skipped,omitempty"`
	Truncated   []string       `json:"truncated,omitempty"`
	PeerTotals  map[string]int `json:"peer_totals,omitempty"`
}

// peerMergeInfo carries the per peer cap detail of a merge.
// It also carries the peers that contributed nothing, split
// by cause: unverified chains and cycle skips.
type peerMergeInfo struct {
	truncated  []string
	totals     map[string]int
	unverified []string
	skipped    []string
}

// filterFromQuery parses the caller event filters out of a
// peer query. Bad from/to values are ignored here. The caller
// endpoint already rejected them.
func filterFromQuery(q url.Values) eventFilter {
	f := eventFilter{
		session:  q.Get("session"),
		tool:     q.Get("tool"),
		kind:     q.Get("kind"),
		decision: q.Get("decision"),
		mode:     q.Get("mode"),
	}
	if v := q.Get("from"); v != "" {
		f.from, _ = time.Parse(time.RFC3339, v)
	}
	if v := q.Get("to"); v != "" {
		f.to, _ = time.Parse(time.RFC3339, v)
	}
	return f
}

// mergePeerEvents pulls filtered events from every peer and
// merges them with the local events. Each peer chain is
// verified here before its events are trusted. A peer whose
// chain fails verification contributes nothing. Rows sort by
// timestamp. Ties sort by gateway name, then by chain
// sequence. The result is stable. A down peer contributes
// nothing and is named in the returned list. A peer whose
// chain did not verify is named in info.unverified, not in
// the down list. A peer already in the visited set is
// skipped, never pulled, and is named in info.skipped. That
// stops mutual peers from recursing.
func (px *Proxy) mergePeerEvents(q url.Values, local []ledger.Event, visited map[string]bool) ([]gatewayEvent, []string, peerMergeInfo) {
	px.peersMu.RLock()
	peers := px.peers
	px.peersMu.RUnlock()
	merged := make([]gatewayEvent, 0, len(local))
	for _, e := range local {
		merged = append(merged, gatewayEvent{Event: e, Gateway: "local"})
	}
	f := filterFromQuery(q)
	type result struct {
		i         int
		events    []ledger.Event
		total     int
		truncated bool
		err       error
		skipped   bool
	}
	results := make([]result, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p PeerConfig) {
			defer wg.Done()
			if visited[p.URL] {
				log.Printf("ledgerline: peer pull cycle: peer %q already visited, skipped", p.Name)
				results[i] = result{i: i, skipped: true}
				return
			}
			chain, _, err := px.fetchVerifiedPeerChain(p, visited)
			if err != nil {
				results[i] = result{i: i, err: err}
				return
			}
			filtered := filterEvents(chain, f)
			total := len(filtered)
			truncated := false
			if total > peerEventCap {
				filtered = filtered[total-peerEventCap:]
				truncated = true
			}
			results[i] = result{i: i, events: filtered, total: total, truncated: truncated}
		}(i, p)
	}
	wg.Wait()
	var down []string
	info := peerMergeInfo{totals: map[string]int{}}
	for i, p := range peers {
		if results[i].skipped {
			info.skipped = append(info.skipped, p.Name)
			continue
		}
		if results[i].err != nil {
			if errors.Is(results[i].err, errPeerChainInvalid) {
				info.unverified = append(info.unverified, p.Name)
			} else {
				down = append(down, p.Name)
			}
			continue
		}
		info.totals[p.Name] = results[i].total
		if results[i].truncated {
			info.truncated = append(info.truncated, p.Name)
		}
		for _, e := range results[i].events {
			merged = append(merged, gatewayEvent{Event: e, Gateway: p.Name})
		}
	}
	sort.SliceStable(merged, func(a, b int) bool {
		if !merged[a].Timestamp.Equal(merged[b].Timestamp) {
			return merged[a].Timestamp.Before(merged[b].Timestamp)
		}
		if merged[a].Gateway != merged[b].Gateway {
			return merged[a].Gateway < merged[b].Gateway
		}
		return merged[a].Seq < merged[b].Seq
	})
	return merged, down, info
}

// peerFilterQuery copies the caller event filters for a peer
// pull. It asks the peer for its own events only. Without
// this, a peer merges its own peers and returns foreign events
// under this peer name. It also lets mutual peers recurse.
// Paging happens here, after the chain is verified. The peer
// query carries no limit or offset.
func peerFilterQuery(q url.Values) url.Values {
	out := url.Values{}
	for _, k := range []string{"session", "tool", "kind", "decision", "mode", "from", "to"} {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	out.Set("gateway", "local")
	return out
}
