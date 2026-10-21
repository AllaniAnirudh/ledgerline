package ledger

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStore persists the event chain in SQLite (pure Go, no cgo).
// Verify recomputes the chain from storage, the same as the
// in-memory store; plain reads return the stored events as written.
// SQLite is durability, not a different trust story.
type SQLiteStore struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS events (
	seq        INTEGER PRIMARY KEY,
	timestamp  TEXT NOT NULL,
	session_id TEXT NOT NULL,
	kind       TEXT NOT NULL,
	tool       TEXT,
	args       TEXT,
	decision   TEXT,
	actor      TEXT,
	prev_hash  TEXT NOT NULL,
	hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
`

// OpenSQLite opens (creating if needed) the ledger database at path.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Parallel agents appending through one gateway can collide on
	// the SQLite write lock; wait briefly instead of failing closed
	// on the first contention.
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// Close releases the database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// Append records one event inside a transaction so the chain can never
// fork under concurrency.
func (s *SQLiteStore) Append(sessionID, kind, tool string, args json.RawMessage, decision, actor string) (Event, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback()

	var lastSeq int64 = -1
	var prevHash string
	err = tx.QueryRow(`SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prevHash)
	if err == sql.ErrNoRows {
		lastSeq, prevHash = -1, ""
	} else if err != nil {
		return Event{}, err
	}

	e := Event{
		Seq:       uint64(lastSeq + 1),
		Timestamp: time.Now().UTC(),
		SessionID: sessionID,
		Kind:      kind,
		Tool:      tool,
		Args:      args,
		Decision:  decision,
		Actor:     actor,
		PrevHash:  prevHash,
	}
	e.Hash = hashEvent(e)

	var argsStr *string
	if len(args) > 0 {
		a := string(args)
		argsStr = &a
	}
	_, err = tx.Exec(
		`INSERT INTO events(seq, timestamp, session_id, kind, tool, args, decision, actor, prev_hash, hash)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Seq, e.Timestamp.Format(time.RFC3339Nano), e.SessionID, e.Kind,
		e.Tool, argsStr, e.Decision, e.Actor, e.PrevHash, e.Hash)
	if err != nil {
		return Event{}, err
	}
	if err := tx.Commit(); err != nil {
		return Event{}, err
	}
	return e, nil
}

// Events returns the whole chain in order.
func (s *SQLiteStore) Events() ([]Event, error) {
	return s.query(`SELECT seq, timestamp, session_id, kind, tool, args, decision, actor, prev_hash, hash FROM events ORDER BY seq`)
}

// EventsBySession returns one session's events in order.
func (s *SQLiteStore) EventsBySession(sessionID string) ([]Event, error) {
	return s.query(`SELECT seq, timestamp, session_id, kind, tool, args, decision, actor, prev_hash, hash FROM events WHERE session_id = ? ORDER BY seq`, sessionID)
}

func (s *SQLiteStore) query(q string, args ...any) ([]Event, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Event
	for rows.Next() {
		var e Event
		var ts, argsStr sql.NullString
		var tool, decision, actor sql.NullString
		if err := rows.Scan(&e.Seq, &ts, &e.SessionID, &e.Kind, &tool, &argsStr, &decision, &actor, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Timestamp, err = time.Parse(time.RFC3339Nano, ts.String)
		if err != nil {
			return nil, fmt.Errorf("bad timestamp in row %d: %w", e.Seq, err)
		}
		e.Tool, e.Decision, e.Actor = tool.String, decision.String, actor.String
		if argsStr.Valid {
			e.Args = json.RawMessage(argsStr.String)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Verify recomputes the whole chain from storage.
func (s *SQLiteStore) Verify() error {
	events, err := s.Events()
	if err != nil {
		return err
	}
	return VerifyEvents(events)
}
