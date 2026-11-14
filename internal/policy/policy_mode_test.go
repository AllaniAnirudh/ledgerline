package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestYAMLModeParsing(t *testing.T) {
	p, err := Parse([]byte(`
version: 1
rules:
  - tool: exec
    action: deny
    mode: detect
  - tool: write_file
    action: hold
    mode: prevent
  - tool: read_file
    action: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	rules := p.Rules()
	if len(rules) != 3 {
		t.Fatalf("want 3 rules, got %d", len(rules))
	}
	if rules[0].Mode != ModeDetect {
		t.Errorf("exec mode = %q, want detect", rules[0].Mode)
	}
	if rules[1].Mode != ModePrevent {
		t.Errorf("write_file mode = %q, want prevent", rules[1].Mode)
	}
	// A rule with no mode means prevent.
	if rules[2].Mode != ModePrevent {
		t.Errorf("read_file mode = %q, want prevent (absent mode)", rules[2].Mode)
	}
	if d, _, mode := p.DecideCall("exec", nil); d != Deny || mode != ModeDetect {
		t.Errorf("exec = %v/%v, want deny/detect", d, mode)
	}
	if d, _, mode := p.DecideCall("write_file", nil); d != Hold || mode != ModePrevent {
		t.Errorf("write_file = %v/%v, want hold/prevent", d, mode)
	}
	// The default has no rule, so its mode is prevent.
	if d, _, mode := p.DecideCall("other", nil); d != Allow || mode != ModePrevent {
		t.Errorf("other = %v/%v, want allow/prevent", d, mode)
	}
}

func TestYAMLModeRejectsUnknown(t *testing.T) {
	bad := []string{
		"version: 1\nrules:\n  - tool: exec\n    action: deny\n    mode: observe\n",
		"version: 1\nrules:\n  - tool: exec\n    action: deny\n    mode: audit\n",
		"version: 1\nrules:\n  - tool: exec\n    action: deny\n    mode: enforce\n",
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", b)
		}
	}
	// Mode matching is case-insensitive. A mixed-case mode parses.
	p, err := Parse([]byte("version: 1\nrules:\n  - tool: exec\n    action: deny\n    mode: Detect\n"))
	if err != nil {
		t.Fatalf("mixed-case detect should parse: %v", err)
	}
	if got := p.Rules()[0].Mode; got != ModeDetect {
		t.Errorf("mode = %q, want detect", got)
	}
}

func TestStaticPoliciesArePrevent(t *testing.T) {
	p := New([]string{"exec"}, []string{"write_file"})
	for _, r := range p.Rules() {
		if r.Mode != ModePrevent {
			t.Errorf("rule %q mode = %q, want prevent", r.Tool, r.Mode)
		}
	}
	if d, _, mode := p.DecideCall("exec", nil); d != Deny || mode != ModePrevent {
		t.Errorf("exec = %v/%v, want deny/prevent", d, mode)
	}
}

func TestDefaultModeFromYAML(t *testing.T) {
	p, err := Parse([]byte("version: 1\ndefault: deny\ndefault_mode: detect\nrules:\n  - tool: exec\n    action: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Default() != Deny {
		t.Errorf("default = %v, want deny", p.Default())
	}
	if p.DefaultMode() != ModeDetect {
		t.Errorf("default mode = %q, want detect", p.DefaultMode())
	}
	// An unmatched call takes the default decision and the
	// default mode. A detect-first rollout now covers it.
	if d, _, mode := p.DecideCall("other", nil); d != Deny || mode != ModeDetect {
		t.Errorf("other = %v/%v, want deny/detect", d, mode)
	}
	// A matched rule still uses its own mode.
	if d, _, mode := p.DecideCall("exec", nil); d != Deny || mode != ModePrevent {
		t.Errorf("exec = %v/%v, want deny/prevent", d, mode)
	}
}

func TestDefaultModeAbsentIsPrevent(t *testing.T) {
	p, err := Parse([]byte("version: 1\ndefault: deny\nrules:\n  - tool: exec\n    action: deny\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.DefaultMode() != ModePrevent {
		t.Errorf("default mode = %q, want prevent (absent default_mode)", p.DefaultMode())
	}
	if d, _, mode := p.DecideCall("other", nil); d != Deny || mode != ModePrevent {
		t.Errorf("other = %v/%v, want deny/prevent", d, mode)
	}
}

func TestDefaultModeRejectsUnknown(t *testing.T) {
	if _, err := Parse([]byte("version: 1\ndefault: deny\ndefault_mode: observe\nrules:\n  - tool: exec\n    action: deny\n")); err == nil {
		t.Error("unknown default_mode should fail")
	}
	// Mode matching is case-insensitive. A mixed-case mode parses.
	p, err := Parse([]byte("version: 1\ndefault: deny\ndefault_mode: Detect\nrules:\n  - tool: exec\n    action: deny\n"))
	if err != nil {
		t.Fatalf("mixed-case default_mode should parse: %v", err)
	}
	if p.DefaultMode() != ModeDetect {
		t.Errorf("default mode = %q, want detect", p.DefaultMode())
	}
}

func TestStaticPolicyDefaultModeIsPrevent(t *testing.T) {
	p := New(nil, nil)
	if p.DefaultMode() != ModePrevent {
		t.Errorf("default mode = %q, want prevent", p.DefaultMode())
	}
	if d, _, mode := p.DecideCall("other", nil); d != Allow || mode != ModePrevent {
		t.Errorf("other = %v/%v, want allow/prevent", d, mode)
	}
}

func TestPolicyHash(t *testing.T) {
	yaml := []byte("version: 1\nrules:\n  - tool: exec\n    action: deny\n")
	p, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}
	// A file policy hashes the file bytes.
	sum := sha256.Sum256(yaml)
	want := hex.EncodeToString(sum[:])
	if p.Hash() != want {
		t.Errorf("hash = %q, want %q", p.Hash(), want)
	}
	// The same bytes hash the same. Different bytes hash differently.
	p2, err := Parse(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if p2.Hash() != p.Hash() {
		t.Error("same policy bytes gave different hashes")
	}
	p3, err := Parse([]byte("version: 1\nrules:\n  - tool: exec\n    action: hold\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p3.Hash() == p.Hash() {
		t.Error("different policy bytes gave the same hash")
	}
	// A static policy hashes its lists. A deny list differs
	// from a hold list with the same tool names.
	if New([]string{"exec"}, nil).Hash() == New(nil, []string{"exec"}).Hash() {
		t.Error("deny and hold lists with the same tools hashed the same")
	}
	if New([]string{"exec"}, nil).Hash() == New([]string{"rm"}, nil).Hash() {
		t.Error("different deny lists hashed the same")
	}
	if h := New(nil, nil).Hash(); len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
		t.Errorf("static hash = %q, want 64 hex chars", h)
	}
}
