package policy

import (
	"encoding/json"
	"testing"
)

// Tests for the bypasses found by the 2026-10-20 adversarial review.
// Argument conditions must fail closed, never open.

func mustParse(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const holdEtc = `
version: 1
default: allow
rules:
  - tool: write_file
    action: hold
    args_match:
      path: "/etc/**"
`

func TestArgsContainsDecodesEscapes(t *testing.T) {
	p := mustParse(t, `
version: 1
default: allow
rules:
  - tool: send_email
    action: hold
    args_contains: "confidential"
`)
	cases := []struct {
		args string
		want Decision
	}{
		{`{"body":"confidential plan"}`, Hold},
		{`{"body":"\u0063onfidential plan"}`, Hold}, // escaped c
		{`{"body":"confi\u0064ential plan"}`, Hold}, // escaped d
		{`{"nested":{"deep":["nothing","CONFIDENTIAL here"]}}`, Hold},
		{`{"body":"hello"}`, Allow},
	}
	for _, c := range cases {
		if got, _ := p.DecideCall("send_email", json.RawMessage(c.args)); got != c.want {
			t.Errorf("args %s: got %v, want %v", c.args, got, c.want)
		}
	}
}

func TestArgsMatchFailsClosedOnShape(t *testing.T) {
	p := mustParse(t, holdEtc)
	cases := []struct {
		args string
		want Decision
	}{
		{`{"path":"/etc/hosts"}`, Hold},
		{`{"path":"/etc/cron.d/evil"}`, Hold},            // subdirectory: ** covers it
		{`{"path":"/tmp/x"}`, Allow},                     // genuinely outside the rule
		{`{"path":123}`, Hold},                           // non-string value: cannot evaluate
		{`{"file":{"path":"/etc/passwd"}}`, Hold},        // matching value nested deeper
		{`{"/etc/passwd"}`, Hold},                        // not an object at all
		{`["/etc/passwd"]`, Hold},                        // array arguments
		{`{"path":"/etc/passwd","path":"/tmp/x"}`, Hold}, // duplicate key
		{`{"path":"/tmp/x","path":"/etc/passwd"}`, Hold}, // duplicate, other order
		{`{"file":{"path":"/tmp/x"}}`, Allow},            // nested, but value does not match
	}
	for _, c := range cases {
		if got, _ := p.DecideCall("write_file", json.RawMessage(c.args)); got != c.want {
			t.Errorf("args %s: got %v, want %v", c.args, got, c.want)
		}
	}
}

func TestArgsMatchDottedPath(t *testing.T) {
	p := mustParse(t, `
version: 1
default: allow
rules:
  - tool: write_file
    action: hold
    args_match:
      file.path: "/etc/**"
`)
	if got, _ := p.DecideCall("write_file", json.RawMessage(`{"file":{"path":"/etc/passwd"}}`)); got != Hold {
		t.Errorf("dotted path nested match: got %v, want hold", got)
	}
	if got, _ := p.DecideCall("write_file", json.RawMessage(`{"file":{"path":"/tmp/x"}}`)); got != Allow {
		t.Errorf("dotted path nested miss: got %v, want allow", got)
	}
}

func TestRecursiveGlob(t *testing.T) {
	p := mustParse(t, holdEtc)
	for _, path := range []string{"/etc/hosts", "/etc/cron.d/evil", "/etc/a/b/c/d"} {
		args := json.RawMessage(`{"path":"` + path + `"}`)
		if got, _ := p.DecideCall("write_file", args); got != Hold {
			t.Errorf("path %s: got %v, want hold", path, got)
		}
	}
	if got, _ := p.DecideCall("write_file", json.RawMessage(`{"path":"/etcx/hosts"}`)); got != Allow {
		t.Errorf("/etcx should not match /etc/**: got %v", got)
	}
}

func TestAllowRuleDoesNotGrantOnUnknown(t *testing.T) {
	p := mustParse(t, `
version: 1
default: deny
rules:
  - tool: write_file
    action: allow
    args_match:
      path: "/tmp/**"
`)
	// Duplicate keys: the allow rule cannot be evaluated, so it must
	// not grant; the deny default applies.
	if got, _ := p.DecideCall("write_file", json.RawMessage(`{"path":"/tmp/x","path":"/tmp/x"}`)); got != Deny {
		t.Errorf("allow rule with broken args: got %v, want deny (default)", got)
	}
	if got, _ := p.DecideCall("write_file", json.RawMessage(`{"path":"/tmp/x"}`)); got != Allow {
		t.Errorf("clean allow: got %v, want allow", got)
	}
}

func TestMultiDocumentRejected(t *testing.T) {
	_, err := Parse([]byte("version: 1\ndefault: allow\n---\nversion: 1\ndefault: deny\n"))
	if err == nil {
		t.Fatal("multi-document policy parsed without error")
	}
}

func TestBadArgsMatchGlobRejected(t *testing.T) {
	_, err := Parse([]byte("version: 1\nrules:\n  - tool: exec\n    action: deny\n    args_match:\n      cmd: 'a['\n"))
	if err == nil {
		t.Fatal("bad args_match glob parsed without error")
	}
}
