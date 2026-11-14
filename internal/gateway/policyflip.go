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
// error when there is no policy file.
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

// servePolicyMode answers POST /v1/policy/mode. It flips one
// rule mode. The actor follows the decideApproval pattern. A
// per-approver token binds the name. A body actor that
// disagrees is rejected. The flip writes the modes file, then
// the ledger event, then swaps the live policy. A ledger
// failure rolls the file back to the old overrides.
func (px *Proxy) servePolicyMode(w http.ResponseWriter, r *http.Request) {
	var req modeFlipRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad mode flip body", http.StatusBadRequest)
		return
	}
	mode, err := policy.ParseMode(req.Mode)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	actor := req.Actor
	if name, bound := px.approverActor(r); bound {
		if actor != "" && actor != name {
			http.Error(w, "actor does not match the approver token", http.StatusForbidden)
			return
		}
		actor = name
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
	next := policy.ModeOverrides{}
	for i, m := range px.policyModes {
		next[i] = m
	}
	next[req.RuleIndex] = mode
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
	oldModes := px.policyModes
	if err := policy.SaveModeOverrides(px.policyModesPath, next); err != nil {
		http.Error(w, "mode override file write failed", http.StatusInternalServerError)
		return
	}
	if _, err := px.ledger.AppendDetailed("gateway", "policy_change", rule.Tool, args, "policy_change", actor, ledger.EventDetail{PolicyHash: newHash}); err != nil {
		// The ledger refused the witness. Roll the file back.
		// The live policy never changed, so the file must not
		// claim it did.
		_ = policy.SaveModeOverrides(px.policyModesPath, oldModes)
		http.Error(w, "ledger write failed", http.StatusInternalServerError)
		return
	}
	px.policy = nextPolicy
	px.policyHash = newHash
	px.policyModes = next
	writeJSON(w, map[string]any{
		"ok": true, "rule_index": req.RuleIndex, "tool": rule.Tool,
		"action": rule.Action.String(), "old_mode": oldMode.String(),
		"new_mode": mode.String(), "policy_hash": newHash,
	})
}
