package gateway

import (
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
)

const testSecret = "brokertest-secret-12345"

func testBrokerFromFile(t *testing.T, yaml string) *Broker {
	t.Helper()
	path := filepath.Join(t.TempDir(), "broker.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBrokerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testBrokerProxy(t *testing.T, upstream http.HandlerFunc, broker *Broker) (*Proxy, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(upstream)
	t.Cleanup(srv.Close)
	px, err := New(srv.URL, ledger.New(), policy.New(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if broker != nil {
		px.SetBroker(broker)
	}
	return px, srv
}

func postToolHeaders(t *testing.T, px *Proxy, tool, args string, headers map[string]string) (int, string) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"` + tool + `","arguments":` + args + `}}`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("X-Ledgerline-Session", "test-session")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestBrokerInjectsAndOverwrites(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, `version: 1
credentials:
  - name: api-key
    header: X-Api-Key
    env: LEDGERLINE_TEST_BROKER_KEY
`)
	seen := make(chan string, 1)
	px, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Get("X-Api-Key")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
	}, b)

	// The agent sends no credential. The gateway injects its own.
	postToolHeaders(t, px, "read_file", `{}`, nil)
	select {
	case got := <-seen:
		if got != testSecret {
			t.Fatalf("upstream should see the brokered value, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never called")
	}

	// The agent sending the matching value passes. It is
	// indistinguishable from the broker's own. It still arrives
	// brokered.
	postToolHeaders(t, px, "read_file", `{}`, map[string]string{"X-Api-Key": testSecret})
	select {
	case got := <-seen:
		if got != testSecret {
			t.Fatalf("upstream should see the brokered value, got %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream never called on second call")
	}
}

func TestBrokerRejectsForeignHeader(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_AUTH", "Bearer "+testSecret)
	b := testBrokerFromFile(t, `version: 1
credentials:
  - name: auth
    header: Authorization
    env: LEDGERLINE_TEST_BROKER_AUTH
`)
	var hits int
	px, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{}`))
	}, b)

	_, body := postToolHeaders(t, px, "read_file", `{}`, map[string]string{"Authorization": "Bearer agent-evil"})
	if !strings.Contains(body, "foreign credential") {
		t.Fatalf("foreign credential should be denied, got %s", body)
	}
	if hits != 0 {
		t.Fatalf("foreign credential must never reach upstream, got %d hits", hits)
	}
}

func TestBrokerDeniesSecretInArgs(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, `version: 1
credentials:
  - name: api-key
    header: X-Api-Key
    env: LEDGERLINE_TEST_BROKER_KEY
`)
	var hits int
	px, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{}`))
	}, b)

	cases := []string{
		`{"token": "` + testSecret + `"}`,
		// Escaped form: decodes to the same secret.
		`{"token": "brokertest-secret-1234\u0035"}`,
	}
	for _, args := range cases {
		_, body := postToolHeaders(t, px, "read_file", args, nil)
		if !strings.Contains(body, "brokered credential") {
			t.Fatalf("args carrying the secret should be denied, got %s", body)
		}
	}
	if hits != 0 {
		t.Fatalf("secret-carrying calls must never reach upstream, got %d hits", hits)
	}
	events, _ := px.Ledger().Events()
	raw, _ := json.Marshal(events)
	if strings.Contains(string(raw), testSecret) {
		t.Fatalf("ledger must never contain the brokered secret: %s", raw)
	}
}

func TestBrokerRedactsResponse(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, `version: 1
credentials:
  - name: api-key
    header: X-Api-Key
    env: LEDGERLINE_TEST_BROKER_KEY
`)
	// Plain JSON response carrying the secret.
	px, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"key is ` + testSecret + `"}]}}`))
	}, b)
	_, body := postToolHeaders(t, px, "read_file", `{}`, nil)
	if strings.Contains(body, testSecret) {
		t.Fatalf("response secret should be redacted, got %s", body)
	}
	if !strings.Contains(body, "[redacted]") {
		t.Fatalf("redaction marker missing, got %s", body)
	}

	// SSE stream carrying the secret in one event line.
	px2, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Write([]byte("event: message\ndata: {\"text\":\"key is " + testSecret + "\"}\n\n"))
	}, b)
	_, body2 := postToolHeaders(t, px2, "read_file", `{}`, nil)
	if strings.Contains(body2, testSecret) {
		t.Fatalf("SSE secret should be redacted, got %s", body2)
	}
	if !strings.Contains(body2, "[redacted]") {
		t.Fatalf("SSE redaction marker missing, got %s", body2)
	}
}

func TestBrokerStatusEndpoint(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	b := testBrokerFromFile(t, `version: 1
credentials:
  - name: api-key
    header: X-Api-Key
    env: LEDGERLINE_TEST_BROKER_KEY
`)
	px, _ := testBrokerProxy(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}, b)
	req := httptest.NewRequest(http.MethodGet, "/v1/broker", nil)
	rec := httptest.NewRecorder()
	px.ServeHTTP(rec, req)
	body := rec.Body.String()
	if !strings.Contains(body, "api-key") || !strings.Contains(body, "X-Api-Key") {
		t.Fatalf("status should list name and header, got %s", body)
	}
	if strings.Contains(body, testSecret) {
		t.Fatalf("status must never expose the value, got %s", body)
	}
}

func TestBrokerConfigErrors(t *testing.T) {
	t.Setenv("LEDGERLINE_TEST_BROKER_KEY", testSecret)
	t.Setenv("LEDGERLINE_TEST_BROKER_SHORT", "abc")
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing env", "version: 1\ncredentials:\n  - name: k\n    header: X-K\n    env: LEDGERLINE_TEST_BROKER_ABSENT\n", "unset or empty"},
		{"unknown field", "version: 1\ncredentials:\n  - name: k\n    header: X-K\n    env: LEDGERLINE_TEST_BROKER_KEY\n    bogus: 1\n", "field"},
		{"duplicate header", "version: 1\ncredentials:\n  - name: a\n    header: X-K\n    env: LEDGERLINE_TEST_BROKER_KEY\n  - name: b\n    header: x-k\n    env: LEDGERLINE_TEST_BROKER_KEY\n", "duplicate header"},
		{"short value", "version: 1\ncredentials:\n  - name: k\n    header: X-K\n    env: LEDGERLINE_TEST_BROKER_SHORT\n", "too short"},
		{"empty", "version: 1\ncredentials: []\n", "no credentials"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "broker.yaml")
		if err := os.WriteFile(path, []byte(c.yaml), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadBrokerFile(path); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
}
