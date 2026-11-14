package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeGatewayResponseSmall(t *testing.T) {
	var list []map[string]any
	err := decodeGatewayResponse(strings.NewReader(`[{"id":"a1"}]`), &list)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0]["id"] != "a1" {
		t.Fatalf("small body should decode to one entry, got %#v", list)
	}
}

func TestDecodeGatewayResponseOverCap(t *testing.T) {
	var v map[string]any
	err := decodeGatewayResponse(strings.NewReader(strings.Repeat("x", maxGatewayResponseBytes+1)), &v)
	if err == nil {
		t.Fatal("body over the cap should fail")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error should name the limit, got %q", err.Error())
	}
}

func TestDecodeGatewayResponseAtCap(t *testing.T) {
	body := `{"k":"` + strings.Repeat("a", maxGatewayResponseBytes-8) + `"}`
	if len(body) != maxGatewayResponseBytes {
		t.Fatalf("test body should sit exactly at the cap, got %d bytes", len(body))
	}
	var v map[string]any
	if err := decodeGatewayResponse(strings.NewReader(body), &v); err != nil {
		t.Fatalf("body at the cap should decode, got %v", err)
	}
	if len(v["k"].(string)) != maxGatewayResponseBytes-8 {
		t.Fatalf("decoded value should keep its full size, got %d bytes", len(v["k"].(string)))
	}
}

func TestFetchApprovalsRejectsOversizeResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(strings.Repeat("x", maxGatewayResponseBytes+1)))
	}))
	defer srv.Close()
	_, err := fetchApprovals(srv.URL, "")
	if err == nil {
		t.Fatal("oversize gateway response should fail")
	}
	if !strings.Contains(err.Error(), "over the") {
		t.Fatalf("error should name the limit, got %q", err.Error())
	}
}
