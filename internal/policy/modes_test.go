package policy

import (
	"os"
	"path/filepath"
	"testing"
)

const modesYAML = `version: 1
default: allow
rules:
  - tool: exec
    action: deny
  - tool: write_file
    action: hold
    mode: detect
`

func TestParseWithOverrides(t *testing.T) {
	base, err := Parse([]byte(modesYAML))
	if err != nil {
		t.Fatal(err)
	}
	// No overrides: same rules, same hash as a plain parse.
	plain, err := ParseWithOverrides([]byte(modesYAML), ModeOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Hash() != base.Hash() {
		t.Fatalf("empty overrides changed the hash: %s vs %s", plain.Hash(), base.Hash())
	}
	// One override: only that rule mode changes, hash changes.
	flipped, err := ParseWithOverrides([]byte(modesYAML), ModeOverrides{0: ModeDetect})
	if err != nil {
		t.Fatal(err)
	}
	rules := flipped.Rules()
	if rules[0].Mode != ModeDetect {
		t.Fatalf("rule 0 mode = %s, want detect", rules[0].Mode)
	}
	if rules[1].Mode != ModeDetect {
		t.Fatalf("rule 1 mode = %s, want detect (unchanged)", rules[1].Mode)
	}
	if rules[0].Action != Deny {
		t.Fatalf("rule 0 action = %s, want deny (flip must not change the action)", rules[0].Action)
	}
	if flipped.Hash() == base.Hash() {
		t.Fatal("override should change the effective hash")
	}
	// Out of range index is a hard error.
	if _, err := ParseWithOverrides([]byte(modesYAML), ModeOverrides{2: ModePrevent}); err == nil {
		t.Fatal("out of range override should fail")
	}
}

func TestModeOverridesRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.modes.json")
	// A missing file means no overrides.
	modes, err := LoadModeOverrides(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(modes) != 0 {
		t.Fatalf("missing file should load no overrides, got %v", modes)
	}
	want := ModeOverrides{1: ModePrevent, 0: ModeDetect}
	base, err := Parse([]byte(modesYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveModeOverrides(path, base, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadModeOverrides(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != ModeDetect || got[1] != ModePrevent {
		t.Fatalf("round trip gave %v, want %v", got, want)
	}
	// The file holds the canonical form. Both entries appear.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"overrides":[{"rule_index":0,"mode":"detect"},{"rule_index":1,"mode":"prevent"}]}` {
		t.Fatalf("modes file = %s", raw)
	}
	// A bad mode in the file is a hard error.
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"overrides":[{"rule_index":0,"mode":"wide"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModeOverrides(bad); err == nil {
		t.Fatal("bad mode in file should fail")
	}
	// Effective hash is stable for the same overrides.
	a := EffectiveHash([]byte(modesYAML), want)
	b := EffectiveHash([]byte(modesYAML), ModeOverrides{0: ModeDetect, 1: ModePrevent})
	if a != b {
		t.Fatal("effective hash must not depend on map order")
	}
}

func TestLoadModeOverridesRejectsDuplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dup.json")
	if err := os.WriteFile(path, []byte(`{"overrides":[{"rule_index":0,"mode":"detect"},{"rule_index":0,"mode":"prevent"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadModeOverrides(path); err == nil {
		t.Fatal("duplicate rule index should fail")
	}
}

func TestSaveModeOverridesPrunesNoopEntries(t *testing.T) {
	base, err := Parse([]byte(modesYAML))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.modes.json")
	// Rule 0 has file mode prevent. An override to prevent
	// changes nothing. It must leave no trace.
	if err := SaveModeOverrides(path, base, ModeOverrides{0: ModePrevent}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"overrides":[]}` {
		t.Fatalf("noop override file = %s, want empty overrides", raw)
	}
	got, err := LoadModeOverrides(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("noop override loaded %v, want none", got)
	}
	// A pruned file hashes to the pristine file hash.
	if EffectiveHash([]byte(modesYAML), got) != base.Hash() {
		t.Fatal("pruned overrides must hash to the pristine hash")
	}
	// A real override survives. A noop beside it is dropped.
	if err := SaveModeOverrides(path, base, ModeOverrides{0: ModeDetect, 1: ModeDetect}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"overrides":[{"rule_index":0,"mode":"detect"}]}` {
		t.Fatalf("mixed override file = %s", raw)
	}
	// A nil base skips pruning. The entry stays as written.
	if err := SaveModeOverrides(path, nil, ModeOverrides{0: ModePrevent}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"overrides":[{"rule_index":0,"mode":"prevent"}]}` {
		t.Fatalf("nil base file = %s", raw)
	}
}

func TestSaveModeOverridesFileMode(t *testing.T) {
	base, err := Parse([]byte(modesYAML))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.modes.json")
	if err := SaveModeOverrides(path, base, ModeOverrides{0: ModeDetect}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("modes file mode = %o, want 0600", st.Mode().Perm())
	}
	// No stray temp file stays behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want 1 (the modes file)", len(entries))
	}
}
