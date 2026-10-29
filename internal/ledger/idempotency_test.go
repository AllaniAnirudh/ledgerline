package ledger

import (
	"path/filepath"
	"testing"
	"time"
)

func idemStores(t *testing.T) map[string]Store {
	t.Helper()
	mem := New()
	sql, err := OpenSQLite(filepath.Join(t.TempDir(), "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Store{"memory": mem, "sqlite": sql}
}

func TestIdemStoreClaim(t *testing.T) {
	for name, s := range idemStores(t) {
		now := time.Now().UTC()
		rec := IdempotencyRecord{Key: "k", SessionID: "s", Tool: "t", ArgsHash: "h", State: IdemStarted, CreatedAt: now, UpdatedAt: now}
		if _, claimed, err := s.IdemClaim(rec); err != nil || !claimed {
			t.Fatalf("%s: fresh claim should win, claimed=%v err=%v", name, claimed, err)
		}
		if _, claimed, err := s.IdemClaim(rec); err != nil || claimed {
			t.Fatalf("%s: second claim should lose, claimed=%v err=%v", name, claimed, err)
		}
		// Terminal-never-ran states free the key again.
		rec.State = IdemDiscarded
		if err := s.IdemPut(rec); err != nil {
			t.Fatal(err)
		}
		if _, claimed, err := s.IdemClaim(rec); err != nil || !claimed {
			t.Fatalf("%s: claim after discarded should win", name)
		}
		rec.State = IdemResolved
		rec.Resolution = "executed"
		if err := s.IdemPut(rec); err != nil {
			t.Fatal(err)
		}
		if _, claimed, err := s.IdemClaim(rec); err != nil || claimed {
			t.Fatalf("%s: claim after resolved-executed should lose", name)
		}
		rec.Resolution = "not-executed"
		if err := s.IdemPut(rec); err != nil {
			t.Fatal(err)
		}
		if _, claimed, err := s.IdemClaim(rec); err != nil || !claimed {
			t.Fatalf("%s: claim after resolved-not-executed should win", name)
		}
		// Purge drops only stale records.
		old := IdempotencyRecord{Key: "old", SessionID: "s", Tool: "t", ArgsHash: "h", State: IdemCompleted, CreatedAt: now.Add(-48 * time.Hour), UpdatedAt: now.Add(-48 * time.Hour)}
		if err := s.IdemPut(old); err != nil {
			t.Fatal(err)
		}
		n, err := s.IdemPurgeBefore(now.Add(-24 * time.Hour))
		if err != nil || n != 1 {
			t.Fatalf("%s: purge should drop 1 stale record, got %d err=%v", name, n, err)
		}
		if _, found, _ := s.IdemGet("s", "old"); found {
			t.Fatalf("%s: stale record should be gone", name)
		}
		if _, found, _ := s.IdemGet("s", "k"); !found {
			t.Fatalf("%s: fresh record should survive purge", name)
		}
	}
}
