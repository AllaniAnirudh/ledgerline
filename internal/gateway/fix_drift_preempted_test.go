package gateway

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Tests for the preempted rule decision (L-N9). In prevent mode
// the drift gate denies before the rule action runs, so the
// recorded decision is marked preempted by drift. In detect
// mode the decision is a would-be decision and carries no mark.

func TestFixDriftPreemptedHoldPrevent(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: hold\n", []listTool{{Name: "read"}})
	before := stub.hits.Load()
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("drifted hold in prevent mode should be denied as drift, got %s", out)
	}
	if stub.hits.Load() != before {
		t.Fatalf("drift-denied call must not reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 2 {
		t.Fatalf("want policy_decision plus tools_drift, got %d: %+v", len(events), events)
	}
	pd, drift := events[0], events[1]
	if pd.Kind != "policy_decision" || pd.Tool != "evil" || pd.Decision != "hold" || pd.Mode != "prevent" {
		t.Fatalf("policy_decision = %+v, want hold/prevent for evil", pd)
	}
	if pd.Preempted != "tools_drift" {
		t.Fatalf("policy_decision preempted = %q, want tools_drift", pd.Preempted)
	}
	if drift.Kind != "tools_drift" || drift.Tool != "evil" || drift.Decision != "deny" || drift.Mode != "prevent" {
		t.Fatalf("tools_drift = %+v, want deny/prevent for evil", drift)
	}
	if drift.DecisionID != pd.DecisionID {
		t.Fatalf("tools_drift id %q does not match policy_decision id %q", drift.DecisionID, pd.DecisionID)
	}
	code, raw := getAPI(t, px, "/v1/sessions")
	if code != http.StatusOK {
		t.Fatalf("GET /v1/sessions: want 200, got %d (%s)", code, raw)
	}
	var rows []sessionRow
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].SessionID != "test-session" {
		t.Fatalf("roster = %v, want one test-session row", rows)
	}
	if rows[0].Denied != 1 {
		t.Fatalf("roster denied = %d, want 1", rows[0].Denied)
	}
	if rows[0].Holds != 0 {
		t.Fatalf("roster holds = %d, want 0: the preempted hold never gated anything", rows[0].Holds)
	}
}

func TestFixDriftPreemptedHoldDetect(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: hold\n    mode: detect\n", []listTool{{Name: "read"}})
	before := stub.hits.Load()
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if strings.Contains(out, "error") {
		t.Fatalf("drifted hold in detect mode should run, got %s", out)
	}
	if stub.hits.Load() != before+1 {
		t.Fatalf("drifted hold in detect mode should reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 3 {
		t.Fatalf("want policy_decision plus tools_drift plus tool_call, got %d: %+v", len(events), events)
	}
	pd, drift, tc := events[0], events[1], events[2]
	if pd.Kind != "policy_decision" || pd.Tool != "evil" || pd.Decision != "hold" || pd.Mode != "detect" {
		t.Fatalf("policy_decision = %+v, want hold/detect for evil", pd)
	}
	if pd.Preempted != "" {
		t.Fatalf("policy_decision preempted = %q, want empty in detect mode", pd.Preempted)
	}
	if drift.Kind != "tools_drift" || drift.Tool != "evil" || drift.Decision != "deny" || drift.Mode != "detect" {
		t.Fatalf("tools_drift = %+v, want deny/detect for evil", drift)
	}
	if tc.Kind != "tool_call" || tc.Tool != "evil" || tc.Decision != "allow" || tc.Mode != "detect" {
		t.Fatalf("tool_call = %+v, want allow/detect for evil", tc)
	}
	if pd.DecisionID == "" || drift.DecisionID != pd.DecisionID || tc.DecisionID != pd.DecisionID {
		t.Fatalf("ids %q, %q, %q should match as one call", pd.DecisionID, drift.DecisionID, tc.DecisionID)
	}
}

func TestFixDriftPreemptedDenyPrevent(t *testing.T) {
	px, stub := driftProxy(t, "version: 1\nrules:\n  - tool: evil\n    action: deny\n", []listTool{{Name: "read"}})
	before := stub.hits.Load()
	_, out := postToolHeaders(t, px, "evil", `{}`, nil)
	if !strings.Contains(out, "not in baseline") {
		t.Fatalf("drifted deny in prevent mode should be denied as drift, got %s", out)
	}
	if stub.hits.Load() != before {
		t.Fatalf("drift-denied call must not reach upstream, hits went %d to %d", before, stub.hits.Load())
	}
	events := sessionEvents(t, px, "test-session")
	if len(events) != 2 {
		t.Fatalf("want policy_decision plus tools_drift, got %d: %+v", len(events), events)
	}
	pd, drift := events[0], events[1]
	if pd.Kind != "policy_decision" || pd.Tool != "evil" || pd.Decision != "deny" || pd.Mode != "prevent" {
		t.Fatalf("policy_decision = %+v, want deny/prevent for evil", pd)
	}
	if pd.Preempted != "tools_drift" {
		t.Fatalf("policy_decision preempted = %q, want tools_drift", pd.Preempted)
	}
	if drift.DecisionID != pd.DecisionID {
		t.Fatalf("tools_drift id %q does not match policy_decision id %q", drift.DecisionID, pd.DecisionID)
	}
}
