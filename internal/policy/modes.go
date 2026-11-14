// Mode overrides persist dashboard mode flips. A flip changes
// only the mode of one rule. It never changes the action. The
// overrides live in a JSON file next to the policy file. The
// file holds one object: {"overrides":[{"rule_index":0,
// "mode":"detect"}]}. A missing file means no overrides. The
// effective policy hash covers the file bytes plus the
// canonical overrides. With no overrides the hash is the plain
// SHA-256 of the file bytes. A flip changes the hash. Later
// policy_decision events carry the new hash.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// ModeOverrides maps a rule index to its flipped mode.
type ModeOverrides map[int]Mode

// modeOverride is one entry in the overrides file.
type modeOverride struct {
	RuleIndex int    `json:"rule_index"`
	Mode      string `json:"mode"`
}

// overridesFile is the on-disk shape of the overrides file.
type overridesFile struct {
	Overrides []modeOverride `json:"overrides"`
}

// canonicalOverrides renders the overrides as compact JSON
// sorted by rule index. The hash uses this form. Two maps with
// the same entries always hash the same.
func canonicalOverrides(o ModeOverrides) ([]byte, error) {
	list := make([]modeOverride, 0, len(o))
	for i, m := range o {
		list = append(list, modeOverride{RuleIndex: i, Mode: m.String()})
	}
	sort.Slice(list, func(a, b int) bool { return list[a].RuleIndex < list[b].RuleIndex })
	return json.Marshal(list)
}

// EffectiveHash returns the policy hash for file bytes with
// overrides applied. With no overrides it is the SHA-256 of
// the file bytes. With overrides it also covers the canonical
// overrides JSON, joined by a zero byte.
func EffectiveHash(fileBytes []byte, o ModeOverrides) string {
	if len(o) == 0 {
		sum := sha256.Sum256(fileBytes)
		return hex.EncodeToString(sum[:])
	}
	canon, err := canonicalOverrides(o)
	if err != nil {
		// Marshal of ints and strings cannot fail.
		panic(err)
	}
	h := sha256.New()
	h.Write(fileBytes)
	h.Write([]byte{0})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil))
}

// LoadModeOverrides reads the overrides file. A missing file
// means no overrides. An empty file means no overrides. A bad
// mode or a negative index is a hard error.
func LoadModeOverrides(path string) (ModeOverrides, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ModeOverrides{}, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return ModeOverrides{}, nil
	}
	var f overridesFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("policy modes: %w", err)
	}
	out := ModeOverrides{}
	for _, e := range f.Overrides {
		if e.RuleIndex < 0 {
			return nil, fmt.Errorf("policy modes: rule index %d is negative", e.RuleIndex)
		}
		m, err := ParseMode(e.Mode)
		if err != nil {
			return nil, fmt.Errorf("policy modes: rule %d: %w", e.RuleIndex, err)
		}
		out[e.RuleIndex] = m
	}
	return out, nil
}

// SaveModeOverrides writes the overrides file. It writes a
// temp file in the same directory and renames it. A reader
// never sees a half-written file. The file mode is 0644.
func SaveModeOverrides(path string, o ModeOverrides) error {
	canon, err := canonicalOverrides(o)
	if err != nil {
		return err
	}
	f := overridesFile{Overrides: []modeOverride{}}
	_ = json.Unmarshal(canon, &f.Overrides)
	if f.Overrides == nil {
		f.Overrides = []modeOverride{}
	}
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ParseWithOverrides builds a policy from YAML bytes and then
// applies mode overrides. An override for an index past the
// last rule is a hard error. The hash is the effective hash.
func ParseWithOverrides(b []byte, o ModeOverrides) (*Policy, error) {
	p, err := Parse(b)
	if err != nil {
		return nil, err
	}
	for i, m := range o {
		if i < 0 || i >= len(p.rules) {
			return nil, fmt.Errorf("policy modes: rule index %d is out of range (policy has %d rules)", i, len(p.rules))
		}
		p.rules[i].Mode = m
	}
	p.hash = EffectiveHash(b, o)
	return p, nil
}
