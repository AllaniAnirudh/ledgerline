// Package policy decides what happens to a tool call at the boundary:
// allow it through, deny it, hold it for human approval, contain the
// session it came from, or record it as a proposal for a human to
// apply out of band.
//
// Policies come from a YAML file (see LoadFile and policy.example.yaml)
// or from static allow/deny/hold lists (New, used by tests and the
// --deny/--hold flags). Rules are evaluated in order; the first match
// wins. A call that matches no rule gets the policy default.
//
// Argument conditions are evaluated on the DECODED JSON arguments,
// never on the raw bytes, and they fail closed: when a rule's tool
// matches but its argument conditions cannot be evaluated (arguments
// unparseable, duplicate keys, a matched value of the wrong shape),
// a deny or hold rule counts as matched and an allow rule counts as
// not matched. A policy condition must never fail open.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Decision is what the boundary does with a tool call.
type Decision int

const (
	Allow Decision = iota
	Deny
	Hold // Hold means "needs a human" before the call may pass.
	// Contain denies this call and freezes its whole session: every
	// further call from the session is denied, and pending held calls
	// from it are denied too.
	Contain
	// Propose records the call as a proposal and never forwards it.
	// A human applies it out of band (or denies it) afterwards.
	Propose
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Hold:
		return "hold"
	case Contain:
		return "contain"
	case Propose:
		return "propose"
	default:
		return "unknown"
	}
}

// ParseDecision converts "allow", "deny", "hold", "contain", or
// "propose" to a Decision.
func ParseDecision(s string) (Decision, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	case "hold":
		return Hold, nil
	case "contain":
		return Contain, nil
	case "propose":
		return Propose, nil
	}
	return Allow, fmt.Errorf("invalid action %q (want allow, deny, hold, contain, or propose)", s)
}

// Rule is one ordered policy rule. Tool is a glob matched
// case-insensitively against the tool name ("*" and "?" work as in
// path.Match). The optional argument conditions narrow the match:
//
//   - ArgsMatch maps a dotted argument path ("path", "file.path") to
//     a glob matched against that argument's string value. Argument
//     globs are case-sensitive and support "**" for "any number of
//     path segments", so "/etc/**" covers /etc/hosts and
//     /etc/cron.d/evil alike.
//   - ArgsContains matches when any decoded string value in the
//     arguments contains the text, case-insensitively. JSON string
//     escapes are decoded first, so the escaped form of a word
//     matches the plain needle too.
//
// A rule whose argument conditions do not hold does not match, and
// evaluation continues to the next rule. Conditions that cannot be
// evaluated fail closed (see the package doc).
type Rule struct {
	Tool         string
	Action       Decision
	Reason       string
	ArgsMatch    map[string]string
	ArgsContains string
}

// Policy is an ordered rule list plus a default decision.
type Policy struct {
	rules []Rule
	def   Decision
}

// New builds a policy from static tool name lists. Deny is checked
// before hold. Empty lists mean "allow everything". List entries are
// tool globs, same as in a policy file.
func New(denyList, holdList []string) *Policy {
	p := &Policy{def: Allow}
	for _, t := range denyList {
		if t = strings.TrimSpace(t); t != "" {
			p.rules = append(p.rules, Rule{Tool: t, Action: Deny})
		}
	}
	for _, t := range holdList {
		if t = strings.TrimSpace(t); t != "" {
			p.rules = append(p.rules, Rule{Tool: t, Action: Hold})
		}
	}
	return p
}

// fileRule mirrors the YAML schema.
type fileRule struct {
	Tool         string            `yaml:"tool"`
	Action       string            `yaml:"action"`
	Reason       string            `yaml:"reason"`
	ArgsMatch    map[string]string `yaml:"args_match"`
	ArgsContains string            `yaml:"args_contains"`
}

type filePolicy struct {
	Version int        `yaml:"version"`
	Default string     `yaml:"default"`
	Rules   []fileRule `yaml:"rules"`
}

// LoadFile reads a YAML policy file. Unknown fields, an unsupported
// version, a bad action, a bad glob, a rule without a tool, or a
// multi-document file are hard errors: a policy that does not parse
// must never silently allow traffic.
func LoadFile(path string) (*Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse builds a policy from YAML bytes.
func Parse(b []byte) (*Policy, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var fp filePolicy
	if err := dec.Decode(&fp); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	// Reject a second document instead of silently dropping it.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("policy: multiple documents in one file are not supported")
		}
		return nil, fmt.Errorf("policy: %w", err)
	}
	if fp.Version != 0 && fp.Version != 1 {
		return nil, fmt.Errorf("policy: unsupported version %d (this build understands version 1)", fp.Version)
	}
	p := &Policy{def: Allow}
	if fp.Default != "" {
		d, err := ParseDecision(fp.Default)
		if err != nil {
			return nil, fmt.Errorf("policy: default: %w", err)
		}
		p.def = d
	}
	for i, fr := range fp.Rules {
		if strings.TrimSpace(fr.Tool) == "" {
			return nil, fmt.Errorf("policy: rule %d has no tool", i+1)
		}
		d, err := ParseDecision(fr.Action)
		if err != nil {
			return nil, fmt.Errorf("policy: rule %d (tool %q): %w", i+1, fr.Tool, err)
		}
		if _, err := path.Match(strings.ToLower(fr.Tool), ""); err != nil {
			return nil, fmt.Errorf("policy: rule %d (tool %q): bad glob: %w", i+1, fr.Tool, err)
		}
		for key, pattern := range fr.ArgsMatch {
			if err := validateValueGlob(pattern); err != nil {
				return nil, fmt.Errorf("policy: rule %d (tool %q): args_match %q: %w", i+1, fr.Tool, key, err)
			}
		}
		p.rules = append(p.rules, Rule{
			Tool:         fr.Tool,
			Action:       d,
			Reason:       fr.Reason,
			ArgsMatch:    fr.ArgsMatch,
			ArgsContains: fr.ArgsContains,
		})
	}
	return p, nil
}

// Rules returns a copy of the policy's rules, in evaluation order.
func (p *Policy) Rules() []Rule {
	out := make([]Rule, len(p.rules))
	copy(out, p.rules)
	return out
}

// Default returns the decision applied when no rule matches.
func (p *Policy) Default() Decision { return p.def }

// Decide returns the decision for a tool call with no argument context.
func (p *Policy) Decide(tool string) Decision {
	d, _ := p.DecideCall(tool, nil)
	return d
}

// DecideCall returns the decision for one tool call and the matching
// rule's reason (empty when the default applied or the rule has none).
func (p *Policy) DecideCall(tool string, args json.RawMessage) (Decision, string) {
	var ev *argsEval // decoded lazily, only if a rule needs it
	for _, r := range p.rules {
		if !globTool(r.Tool, tool) {
			continue
		}
		if r.ArgsContains == "" && len(r.ArgsMatch) == 0 {
			return r.Action, r.Reason
		}
		if ev == nil {
			ev = evaluateArgs(args)
		}
		switch evalRule(r, ev) {
		case matchYes:
			return r.Action, r.Reason
		case matchUnknown:
			// Fail closed: a restrictive rule whose conditions
			// cannot be evaluated counts as matched; an allow
			// rule in that state grants nothing. Contain and
			// propose are restrictive: neither forwards the call.
			if r.Action == Deny || r.Action == Hold || r.Action == Contain || r.Action == Propose {
				reason := r.Reason
				if reason == "" {
					reason = "arguments could not be fully evaluated"
				}
				return r.Action, reason
			}
		}
	}
	return p.def, ""
}

// --- tool glob (case-insensitive) ---

func globTool(pattern, name string) bool {
	ok, err := path.Match(strings.ToLower(pattern), strings.ToLower(name))
	if err != nil {
		// A malformed pattern from the static lists matches literally.
		return strings.EqualFold(pattern, name)
	}
	return ok
}

// --- argument value glob (case-sensitive, "**" crosses "/") ---

func validateValueGlob(pattern string) error {
	for _, seg := range strings.Split(pattern, "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("bad glob segment %q: %w", seg, err)
		}
	}
	return nil
}

func globValue(pattern, value string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(value, "/"))
}

func matchSegments(pat, val []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			// "**" consumes zero or more whole segments.
			for skip := 0; skip <= len(val); skip++ {
				if matchSegments(pat[1:], val[skip:]) {
					return true
				}
			}
			return false
		}
		if len(val) == 0 {
			return false
		}
		ok, err := path.Match(pat[0], val[0])
		if err != nil || !ok {
			return false
		}
		pat, val = pat[1:], val[1:]
	}
	return len(val) == 0
}

// --- decoded argument evaluation ---

type matchResult int

const (
	matchNo matchResult = iota
	matchYes
	matchUnknown // conditions cannot be evaluated; caller fails closed
)

// argsEval is the decoded view of one call's arguments.
type argsEval struct {
	root     any      // decoded JSON value (nil when no arguments)
	hasArgs  bool     // arguments were present at all
	broken   bool     // unparseable, or duplicate keys somewhere
	strings  []string // every decoded string value, recursively
	leafVals map[string][]string
}

func evaluateArgs(args json.RawMessage) *argsEval {
	ev := &argsEval{leafVals: map[string][]string{}}
	if len(args) == 0 {
		return ev
	}
	ev.hasArgs = true
	dec := json.NewDecoder(bytes.NewReader(args))
	v, err := readValue(dec, ev)
	if err != nil {
		ev.broken = true
		return ev
	}
	ev.root = v
	// Anything after the first JSON value makes the shape ambiguous.
	if _, err := dec.Token(); err != io.EOF {
		ev.broken = true
	}
	return ev
}

// readValue decodes one JSON value from the token stream, recording
// string values and flagging duplicate object keys as it goes.
func readValue(dec *json.Decoder, ev *argsEval) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			seen := map[string]bool{}
			for dec.More() {
				ktok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := ktok.(string)
				if !ok {
					return nil, fmt.Errorf("non-string object key")
				}
				if seen[key] {
					ev.broken = true // duplicate key: parsers disagree on the winner
				}
				seen[key] = true
				v, err := readValue(dec, ev)
				if err != nil {
					return nil, err
				}
				obj[key] = v
				if s, ok := v.(string); ok {
					ev.leafVals[key] = append(ev.leafVals[key], s)
				}
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			var arr []any
			for dec.More() {
				v, err := readValue(dec, ev)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err := dec.Token()
			return arr, err
		}
		return nil, fmt.Errorf("unexpected delimiter %q", t)
	case string:
		ev.strings = append(ev.strings, t)
		return t, nil
	default:
		return tok, nil // float64, bool, nil
	}
}

func evalRule(r Rule, ev *argsEval) matchResult {
	unknown := false

	if r.ArgsContains != "" {
		if ev.broken {
			unknown = true
		} else {
			needle := strings.ToLower(r.ArgsContains)
			found := false
			for _, s := range ev.strings {
				if strings.Contains(strings.ToLower(s), needle) {
					found = true
					break
				}
			}
			if !found {
				return matchNo
			}
		}
	}

	for key, pattern := range r.ArgsMatch {
		switch evalArgsMatch(key, pattern, ev) {
		case matchNo:
			return matchNo
		case matchUnknown:
			unknown = true
		}
	}

	if unknown {
		return matchUnknown
	}
	return matchYes
}

func evalArgsMatch(dottedKey, pattern string, ev *argsEval) matchResult {
	if ev.broken {
		return matchUnknown
	}
	if !ev.hasArgs {
		return matchNo
	}
	// Walk the dotted path from the root.
	cur := ev.root
	parts := strings.Split(dottedKey, ".")
	for i, part := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return matchUnknown // path crosses a non-object
		}
		v, present := obj[part]
		if !present {
			if i == len(parts)-1 {
				// The leaf name may live deeper, in a shape this
				// rule does not address. If a nested value with
				// this name would match the pattern, the rule
				// cannot be cleared: fail closed.
				for _, s := range ev.leafVals[part] {
					if globValue(pattern, s) {
						return matchUnknown
					}
				}
			}
			return matchNo
		}
		cur = v
	}
	s, ok := cur.(string)
	if !ok {
		return matchUnknown // present but not a string: cannot evaluate
	}
	if globValue(pattern, s) {
		return matchYes
	}
	return matchNo
}
