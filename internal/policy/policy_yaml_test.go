package policy

import (
	"encoding/json"
	"testing"
)

const sampleYAML = `
version: 1
default: allow
rules:
  - tool: exec
    action: deny
    reason: "shell access is off limits"
  - tool: "delete_*"
    action: deny
  - tool: write_file
    action: hold
    args_match:
      path: "/etc/*"
  - tool: write_file
    action: allow
  - tool: send_email
    action: hold
    args_contains: "confidential"
`

func TestYAMLPolicy(t *testing.T) {
	p, err := Parse([]byte(sampleYAML))
	if err != nil {
		t.Fatal(err)
	}
	args := func(s string) json.RawMessage { return json.RawMessage(s) }
	cases := []struct {
		tool   string
		args   json.RawMessage
		want   Decision
		reason string
	}{
		{"exec", nil, Deny, "shell access is off limits"},
		{"EXEC", nil, Deny, "shell access is off limits"},
		{"delete_file", nil, Deny, ""},                          // glob rule
		{"write_file", args(`{"path":"/etc/hosts"}`), Hold, ""}, // args_match hits
		{"write_file", args(`{"path":"/tmp/x"}`), Allow, ""},    // falls to next write_file rule
		{"write_file", nil, Allow, ""},                          // no args: args_match rule skipped
		{"send_email", args(`{"body":"CONFIDENTIAL plan"}`), Hold, ""},
		{"send_email", args(`{"body":"hello"}`), Allow, ""}, // args_contains misses, default applies
		{"read_file", nil, Allow, ""},
	}
	for _, c := range cases {
		got, reason := p.DecideCall(c.tool, c.args)
		if got != c.want {
			t.Errorf("DecideCall(%q, %s) = %v, want %v", c.tool, c.args, got, c.want)
		}
		if reason != c.reason {
			t.Errorf("DecideCall(%q) reason = %q, want %q", c.tool, reason, c.reason)
		}
	}
}

func TestYAMLDefaultDeny(t *testing.T) {
	p, err := Parse([]byte("version: 1\ndefault: deny\nrules:\n  - tool: read_file\n    action: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Decide("read_file"); got != Allow {
		t.Errorf("read_file = %v, want allow", got)
	}
	if got := p.Decide("anything_else"); got != Deny {
		t.Errorf("unlisted tool = %v, want deny (default)", got)
	}
}

func TestYAMLRejectsBadFiles(t *testing.T) {
	bad := []string{
		"version: 99\nrules: []\n",                               // unsupported version
		"version: 1\nrules:\n  - tool: x\n    action: maybe\n",   // bad action
		"version: 1\nrules:\n  - action: deny\n",                 // rule without tool
		"version: 1\nrules:\n  - tool: 'a['\n    action: deny\n", // bad glob
		"version: 1\nbogus_field: true\n",                        // unknown field
		"version: 1\ndefault: sometimes\n",                       // bad default
		"version: 1\nrules: [unclosed\n",                         // broken YAML
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", b)
		}
	}
}
