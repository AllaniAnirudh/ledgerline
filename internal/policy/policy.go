// Package policy decides what happens to a tool call at the boundary:
// allow it through, deny it, or hold it for human approval.
//
// v0 is a static list policy. The YAML policy file and the approval
// UX (the human side of Hold) land with the Phase 1 wedge.
package policy

import "strings"

// Decision is what the boundary does with a tool call.
type Decision int

const (
	Allow Decision = iota
	Deny
	// Hold means "needs a human". v0 has no approval UX yet, so Hold
	// is answered with a deny plus a ledger record. The record is the
	// point: the held call is witnessed either way.
	Hold
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	default:
		return "hold"
	}
}

// Policy is a static allow-by-default list policy.
type Policy struct {
	deny map[string]bool
	hold map[string]bool
}

// New builds a policy from comma-separated tool name lists.
// Matching is case-insensitive. Empty lists mean "allow everything".
func New(denyList, holdList []string) *Policy {
	p := &Policy{deny: map[string]bool{}, hold: map[string]bool{}}
	for _, t := range denyList {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			p.deny[t] = true
		}
	}
	for _, t := range holdList {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			p.hold[t] = true
		}
	}
	return p
}

// Decide returns the decision for one tool call.
func (p *Policy) Decide(tool string) Decision {
	t := strings.ToLower(strings.TrimSpace(tool))
	if p.deny[t] {
		return Deny
	}
	if p.hold[t] {
		return Hold
	}
	return Allow
}
