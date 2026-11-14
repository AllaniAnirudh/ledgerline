// Peer gateways feed the dashboard pull. Each peer keeps its
// own SQLite chain. This gateway asks each peer for its chain
// verify result and its event count, and merges event timelines
// on demand. A peer that does not answer shows as down. It is
// never silent. The merged timeline sorts by timestamp. It
// never claims one global chain order.
package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// peerTimeout bounds one peer request. A slow peer must not
// stall the dashboard. Five seconds is the cap.
const peerTimeout = 5 * time.Second

// peerEventCap bounds one peer pull in a merged timeline. A
// peer with more filtered events than this contributes its
// newest rows first. The cap keeps one merge bounded.
const peerEventCap = 500

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
// URLs must parse and use http or https.
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
	}
	if peers == nil {
		peers = []PeerConfig{}
	}
	return peers, nil
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

// peerVerify is the shape of a peer's GET /v1/verify answer.
type peerVerify struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// fetchPeerVerify asks one peer to verify its chain.
func (px *Proxy) fetchPeerVerify(p PeerConfig) (bool, string, error) {
	req, err := http.NewRequest(http.MethodGet, p.URL+"/v1/verify", nil)
	if err != nil {
		return false, "", err
	}
	if p.Token != "" {
		req.Header.Set("X-Ledgerline-Token", p.Token)
	}
	resp, err := px.peerClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("verify answered HTTP %d", resp.StatusCode)
	}
	var v peerVerify
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return false, "", fmt.Errorf("verify answer did not parse: %w", err)
	}
	return v.OK, v.Error, nil
}

// fetchPeerEvents asks one peer for filtered events. Query
// params carry the caller filters. The answer is the peer
// events plus the peer total before paging.
func (px *Proxy) fetchPeerEvents(p PeerConfig, q url.Values) ([]ledger.Event, int, error) {
	u := p.URL + "/v1/events?" + q.Encode()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
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
	var r eventsResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, 0, fmt.Errorf("events answer did not parse: %w", err)
	}
	return r.Events, r.Total, nil
}

// peerStatusFor builds one peer row. Verify and the event count
// run in order. A verify failure still reports the peer as
// reachable. Only a failed request reports it as down.
func (px *Proxy) peerStatusFor(p PeerConfig) peerStatus {
	st := peerStatus{Name: p.Name, URL: p.URL}
	ok, verr, err := px.fetchPeerVerify(p)
	if err != nil {
		st.Error = err.Error()
		return st
	}
	st.Reachable = true
	st.LastSync = time.Now().UTC().Format(time.RFC3339Nano)
	st.ChainOK = ok
	st.ChainError = verr
	q := url.Values{}
	q.Set("limit", "1")
	_, total, err := px.fetchPeerEvents(p, q)
	if err != nil {
		st.Error = err.Error()
		return st
	}
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
// during the merge. Their events are absent, not silent.
type mergedEventsResponse struct {
	Events      []gatewayEvent `json:"events"`
	Total       int            `json:"total"`
	Limit       int            `json:"limit"`
	Offset      int            `json:"offset"`
	MergedBy    string         `json:"merged_by,omitempty"`
	Unreachable []string       `json:"unreachable,omitempty"`
}

// mergePeerEvents pulls filtered events from every peer and
// merges them with the local events. Rows sort by timestamp.
// Ties sort by gateway name, then by chain sequence. The
// result is stable. A down peer contributes nothing and is
// named in the returned list.
func (px *Proxy) mergePeerEvents(q url.Values, local []ledger.Event) ([]gatewayEvent, []string) {
	px.peersMu.RLock()
	peers := px.peers
	px.peersMu.RUnlock()
	merged := make([]gatewayEvent, 0, len(local))
	for _, e := range local {
		merged = append(merged, gatewayEvent{Event: e, Gateway: "local"})
	}
	type result struct {
		i      int
		events []ledger.Event
		err    error
	}
	results := make([]result, len(peers))
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Add(1)
		go func(i int, p PeerConfig) {
			defer wg.Done()
			events, _, err := px.fetchPeerEvents(p, q)
			results[i] = result{i: i, events: events, err: err}
		}(i, p)
	}
	wg.Wait()
	var down []string
	for i, p := range peers {
		if results[i].err != nil {
			down = append(down, p.Name)
			continue
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
	return merged, down
}

// peerFilterQuery copies the caller event filters for a peer
// pull. Paging is capped per peer. The merge pages the merged
// list itself.
func peerFilterQuery(q url.Values) url.Values {
	out := url.Values{}
	for _, k := range []string{"session", "tool", "kind", "decision", "mode", "from", "to"} {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	out.Set("limit", strconv.Itoa(peerEventCap))
	out.Set("offset", "0")
	return out
}
