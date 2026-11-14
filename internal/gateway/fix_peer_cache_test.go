package gateway

import (
	"testing"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
)

// Tests for the struct-scoped peer chain cache (L-N8). The cache
// lives on the Proxy, and SetPeers clears it, so a removed
// peer's chain never survives a peer reload.

func TestFixSetPeersClearsCache(t *testing.T) {
	px, _ := testProxy(t)
	chain := []ledger.Event{{Seq: 0, Hash: "a"}, {Seq: 1, Hash: "b"}}
	px.storePeerChain("http://127.0.0.1:9", chain, 2)
	if _, ok := px.cachedPeerChainFor("http://127.0.0.1:9"); !ok {
		t.Fatal("chain should be cached after store")
	}
	px.SetPeers([]PeerConfig{{Name: "other", URL: "http://127.0.0.1:10"}})
	if _, ok := px.cachedPeerChainFor("http://127.0.0.1:9"); ok {
		t.Fatal("removed peer chain survived SetPeers")
	}
}

func TestFixPeerCacheScopedPerProxy(t *testing.T) {
	px1, _ := testProxy(t)
	px2, _ := testProxy(t)
	px1.storePeerChain("http://127.0.0.1:9", []ledger.Event{{Seq: 0, Hash: "a"}}, 1)
	if _, ok := px2.cachedPeerChainFor("http://127.0.0.1:9"); ok {
		t.Fatal("one gateway's cache leaked into another gateway")
	}
}
