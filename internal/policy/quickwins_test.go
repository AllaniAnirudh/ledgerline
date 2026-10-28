package policy

import (
	"encoding/json"
	"testing"
)

func TestParseContainPropose(t *testing.T) {
	if d, err := ParseDecision("contain"); err != nil || d != Contain {
		t.Fatalf("contain should parse, got %v %v", d, err)
	}
	if d, err := ParseDecision("propose"); err != nil || d != Propose {
		t.Fatalf("propose should parse, got %v %v", d, err)
	}
	if Contain.String() != "contain" || Propose.String() != "propose" {
		t.Fatalf("bad String: %q %q", Contain.String(), Propose.String())
	}
	if _, err := ParseDecision("explode"); err == nil {
		t.Fatal("unknown action should fail")
	}
}

func TestContainProposeDecisions(t *testing.T) {
	p, err := Parse([]byte(`version: 1
default: allow
rules:
  - tool: rm
    action: contain
  - tool: deploy
    action: propose
`))
	if err != nil {
		t.Fatal(err)
	}
	if d, _ := p.DecideCall("rm", nil); d != Contain {
		t.Fatalf("rm should contain, got %v", d)
	}
	if d, _ := p.DecideCall("deploy", nil); d != Propose {
		t.Fatalf("deploy should propose, got %v", d)
	}
	if d, _ := p.DecideCall("read_file", nil); d != Allow {
		t.Fatalf("read_file should allow, got %v", d)
	}
}

// Contain and propose are restrictive: when their argument
// conditions cannot be evaluated, they count as matched, exactly
// like deny and hold. An allow rule in that state grants nothing.
func TestContainProposeFailClosed(t *testing.T) {
	p, err := Parse([]byte(`version: 1
default: allow
rules:
  - tool: write_file
    action: contain
    args_match:
      path: "/etc/**"
  - tool: deploy
    action: propose
    args_match:
      env: "prod"
`))
	if err != nil {
		t.Fatal(err)
	}
	// Unparseable arguments: conditions cannot be evaluated.
	broken := json.RawMessage(`{"path": `)
	if d, _ := p.DecideCall("write_file", broken); d != Contain {
		t.Fatalf("unparseable args should contain, got %v", d)
	}
	if d, _ := p.DecideCall("deploy", broken); d != Propose {
		t.Fatalf("unparseable args should propose, got %v", d)
	}
}
