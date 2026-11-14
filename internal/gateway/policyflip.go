// Policy read and mode flip for the dashboard. The flip
// changes only one rule mode. It never changes the action. The
// flip is witnessed in the ledger as a policy_change event. It
// persists in the modes file next to the policy file. A
// gateway that runs on static --deny/--hold lists has no
// policy file. It answers 400 to a flip.
package gateway

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/AllaniAnirudh/ledgerline/internal/ledger"
	"github.com/AllaniAnirudh/ledgerline/internal/policy"
)

// policyRuleRow is one rule of GET /v1/policy.
type policyRuleRow struct {
	Index  int    `json:"index"`
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Mode   string `json:"mode"`
	Reason string `json:"reason"`
}

// policyResponse is the shape of GET /v1/policy.
type policyResponse struct {
	Rules      []policyRuleRow `json:"rules"`
	PolicyHash string          `json:"policy_hash"`
}

// servePolicy answers GET /v1/policy. It lists the rules in
// evaluation order with the effective policy hash.
func (px *Proxy) servePolicy(w http.ResponseWriter, r *http.Request) {
	p := px.policyNow()
	rules := p.Rules()
	rows := make([]policyRuleRow, 0, len(rules))
	for i, rule := range rules {
		rows = append(rows, policyRuleRow{
			Index:  i,
			Tool:   rule.Tool,
			Action: rule.Action.String(),
			Mode:   rule.Mode.String(),
			Reason: rule.Reason,
		})
	}
	writeJSON(w, policyResponse{Rules: rows, PolicyHash: px.policyHashNow()})
}

// modeFlipRequest is the body of POST /v1/policy/mode.
type modeFlipRequest struct {
	RuleIndex int    `json:"rule_index"`
	Mode      string `json:"mode"`
	Actor     string `json:"actor"`
}

// LoadPolicyModes reloads the modes file and re-applies it to
// the policy. It is the restart path. A gateway that starts
// with a modes file on disk picks its flips back up. It needs
// the policy file bytes from SetPolicySource. It returns an
// error when there is no policy file. It reconciles the modes
// file against the ledger first. See reconcileModesLocked.
func (px *Proxy) LoadPolicyModes(path string) error {
	modes, err := policy.LoadModeOverrides(path)
	if err != nil {
		return err
	}
	px.policyMu.Lock()
	defer px.policyMu.Unlock()
	if px.policyFileBytes == nil {
		return fmt.Errorf("mode flips need a policy file")
	}
	base, err := policy.Parse(px.policyFileBytes)
	if err != nil {
		return err
	}
	modes = px.reconcileModesLocked(path, base, modes)
	p, err := policy.ParseWithOverrides(px.policyFileBytes, modes)
	if err != nil {
		return err
	}
	px.policy = p
	px.policyHash = p.Hash()
	px.policyModes = modes
	px.policyModesPath = path
	return nil
}

// policyChangeArgs is the args shape of a policy_change event.
// The flip handler writes it. Reconciliation reads it back.
type policyChangeArgs struct {
	RuleIndex int    `json:"rule_index"`
	NewMode   string `json:"new_mode"`
}

// reconcileModesLocked compares the modes file with the latest
// policy_change events in the ledger. The caller holds the
// policy write lock. The ledger is the source of truth. A flip
// witnessed there must apply, even when the modes file lost it
// in a crash between the witness and the file write. That is
// the fail-unsafe window the witness-first flip order closes
// going forward. Old crashes still need repair here.
//
// When the file and the ledger disagree, the flips are rebuilt
// by replaying every policy_change event in order. The rebuild
// must hash to the latest event hash for this policy file.
// When it does, the file is repaired from the ledger and the
// repair is logged loudly. When it does not, the events do not
// fit this policy file (the file was replaced since the flips),
// so the file stands and the mismatch is logged loudly. When
// the ledger holds no policy_change events, the file stands:
// a fresh ledger cannot judge an old file.
func (px *Proxy) reconcileModesLocked(path string, base *policy.Policy, fileModes policy.ModeOverrides) policy.ModeOverrides {
	fileModes = policy.PruneModeOverrides(base, fileModes)
	if px.ledger == nil {
		log.Printf("mode flip reconciliation: no ledger; modes file stands")
		return fileModes
	}
	events, err := px.ledger.EventsBySession("gateway")
	if err != nil {
		log.Printf("mode flip reconciliation: cannot read ledger events: %v; modes file stands", err)
		return fileModes
	}
	var latest *ledger.Event
	replayed := policy.ModeOverrides{}
	for i := range events {
		e := events[i]
		if e.Kind != "policy_change" {
			continue
		}
		var args policyChangeArgs
		if err := json.Unmarshal(e.Args, &args); err != nil {
			log.Printf("mode flip reconciliation: policy_change event %d has unreadable args; modes file stands", e.Seq)
			return fileModes
		}
		m, err := policy.ParseMode(args.NewMode)
		if err != nil {
			log.Printf("mode flip reconciliation: policy_change event %d names unknown mode %q; modes file stands", e.Seq, args.NewMode)
			return fileModes
		}
		replayed[args.RuleIndex] = m
		latest = &events[i]
	}
	if latest == nil {
		return fileModes
	}
	if latest.PolicyHash == policy.EffectiveHash(px.policyFileBytes, fileModes) {
		return fileModes
	}
	repaired := policy.PruneModeOverrides(base, replayed)
	if _, err := policy.ParseWithOverrides(px.policyFileBytes, repaired); err != nil {
		log.Printf("mode flip reconciliation: ledger flips do not fit this policy file (%v); modes file stands", err)
		return fileModes
	}
	if policy.EffectiveHash(px.policyFileBytes, repaired) != latest.PolicyHash {
		log.Printf("mode flip reconciliation: rebuilt flips hash %s, latest policy_change event %d says %s; modes file stands", policy.EffectiveHash(px.policyFileBytes, repaired), latest.Seq, latest.PolicyHash)
		return fileModes
	}
	log.Printf("mode flip reconciliation: modes file disagrees with the ledger (latest policy_change event %d, hash %s); repairing the modes file from the ledger", latest.Seq, latest.PolicyHash)
	if err := policy.SaveModeOverrides(path, base, repaired); err != nil {
		log.Printf("mode flip reconciliation: modes file repair failed: %v; ledger state applies in memory only", err)
	}
	return repaired
}

// servePolicyMode answers POST /v1/policy/mode. It flips one
// rule mode. The actor follows the decideApproval pattern. A
// per-approver token binds the name. A body actor that
// disagrees is rejected. When approver tokens are configured,
// a flip needs one: a flip with only the shared control token
// carries no credential for its actor, so it is refused. When
// no approver token is configured, no credential binds any
// name. The ledger then records the flip as "unattributed"
// instead of trusting the body value. A body actor in that
// case is ignored, not recorded.
//
// The flip order is witness first, then file write, then live
// swap, all under one lock. The old order wrote the file
// first. A crash between the file write and the ledger append
// left an unwitnessed flip that applied on restart. The new
// order cannot lose a flip from the audit trail. A crash after
// the witness leaves the file behind. Startup reconciliation
// in LoadPolicyModes repairs the file from the ledger. A file
// write failure after the witness is logged loudly with the
// hash and returned to the caller. The live policy never
// changes on a failed flip. There is no file rollback: the
// file is untouched until the rename, and the ledger is the
// source of truth.
func (px *Proxy) servePolicyMode(w http.ResponseWriter, r *http.Request) {
	var req modeFlipRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxControlBodyBytes)).Decode(&req); err != nil {
		http.Error(w, "bad mode flip body", http.StatusBadRequest)
		return
	}
	mode, err := policy.ParseMode(req.Mode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := ""
	if name, bound := px.approverActor(r); bound {
		if req.Actor != "" && req.Actor != name {
			http.Error(w, "actor does not match the approver token", http.StatusForbidden)
			return
		}
		actor = name
	} else if len(px.approvers) > 0 {
		http.Error(w, "mode flips need a per-approver token", http.StatusForbidden)
		return
	} else {
		actor = "unattributed"
	}

	px.policyMu.Lock()
	defer px.policyMu.Unlock()
	if px.policyFileBytes == nil {
		http.Error(w, "mode flips need a policy file; this gateway runs on static deny and hold lists", http.StatusBadRequest)
		return
	}
	rules := px.policy.Rules()
	if req.RuleIndex < 0 || req.RuleIndex >= len(rules) {
		http.Error(w, fmt.Sprintf("rule index %d is out of range (policy has %d rules)", req.RuleIndex, len(rules)), http.StatusBadRequest)
		return
	}
	rule := rules[req.RuleIndex]
	oldMode := rule.Mode
	if oldMode == mode {
		writeJSON(w, map[string]any{"ok": true, "rule_index": req.RuleIndex, "tool": rule.Tool, "action": rule.Action.String(), "old_mode": oldMode.String(), "new_mode": mode.String(), "policy_hash": px.policyHash, "unchanged": true})
		return
	}
	base, err := policy.Parse(px.policyFileBytes)
	if err != nil {
		http.Error(w, "mode flip failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	next := policy.ModeOverrides{}
	for i, m := range px.policyModes {
		next[i] = m
	}
	next[req.RuleIndex] = mode
	next = policy.PruneModeOverrides(base, next)
	nextPolicy, err := policy.ParseWithOverrides(px.policyFileBytes, next)
	if err != nil {
		http.Error(w, "mode flip failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	newHash := nextPolicy.Hash()
	args, _ := json.Marshal(map[string]any{
		"rule_index":  req.RuleIndex,
		"tool":        rule.Tool,
		"action":      rule.Action.String(),
		"old_mode":    oldMode.String(),
		"new_mode":    mode.String(),
		"policy_hash": newHash,
	})
	// Witness first. A flip with no ledger event never
	// applies. A ledger failure stops the flip here.
	if _, err := px.ledger.AppendDetailed("gateway", "policy_change", rule.Tool, args, "policy_change", actor, ledger.EventDetail{PolicyHash: newHash}); err != nil {
		http.Error(w, "ledger write failed", http.StatusInternalServerError)
		return
	}
	// Then the file. The witness already exists, so a
	// failure here is loud and visible. Startup
	// reconciliation repairs the file from the ledger.
	if err := policy.SaveModeOverrides(px.policyModesPath, base, next); err != nil {
		log.Printf("mode flip witnessed in ledger (policy hash %s) but modes file write failed: %v; startup reconciliation repairs the file from the ledger", newHash, err)
		http.Error(w, "mode override file write failed after ledger witness: "+err.Error(), http.StatusInternalServerError)
		return
	}
	// Then the live swap. The file and the ledger agree.
	px.policy = nextPolicy
	px.policyHash = newHash
	px.policyModes = next
	writeJSON(w, map[string]any{
		"ok": true, "rule_index": req.RuleIndex, "tool": rule.Tool,
		"action": rule.Action.String(), "old_mode": oldMode.String(),
		"new_mode": mode.String(), "policy_hash": newHash,
	})
}
