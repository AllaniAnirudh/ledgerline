package ledger

import "time"

// BaselineTool is one upstream tool as the gateway trusts it. It
// carries a name, a description, and the canonical input schema.
// The baseline is the trust anchor for drift detection. A tool
// name outside it is denied until a human accepts a new baseline.
type BaselineTool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Schema      string `json:"schema"` // canonical inputSchema JSON, "" when absent
}

// ToolsBaseline is one observed tool surface. It carries the
// tools sorted by name, plus the hash that identifies that exact
// surface.
type ToolsBaseline struct {
	Tools     []BaselineTool
	Hash      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ToolsBaselineGet returns the stored baseline. It returns false
// when none was ever established.
func (l *Ledger) ToolsBaselineGet() (ToolsBaseline, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.baseline == nil {
		return ToolsBaseline{}, false, nil
	}
	return *l.baseline, true, nil
}

// ToolsBaselinePut stores the baseline, replacing any previous one.
func (l *Ledger) ToolsBaselinePut(b ToolsBaseline) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	cp := b
	l.baseline = &cp
	return nil
}
