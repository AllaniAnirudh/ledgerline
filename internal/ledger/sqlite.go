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
// in-memory store. Plain reads return the stored events as
// written. SQLite is durability, not a different trust story.
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
CREATE TABLE IF NOT EXISTS tools_baseline (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	tools_json TEXT NOT NULL,
	hash       TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency (
	session_id   TEXT NOT NULL,
	key          TEXT NOT NULL,
	tool         TEXT NOT NULL,
	args_hash    TEXT NOT NULL,
	state        TEXT NOT NULL,
	approval_id  TEXT,
	status       INTEGER,
	content_type TEXT,
	body         BLOB,
	body_too_large INTEGER NOT NULL DEFAULT 0,
	resolution   TEXT,
	note         TEXT,
	created_at   TEXT NOT NULL,
	updated_at   TEXT NOT NULL,
	PRIMARY KEY (session_id, key)
);
`

// OpenSQLite opens the ledger database at path. It creates the
// database if needed.
func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	// Parallel agents appending through one gateway can collide
	// on the SQLite write lock. Wait briefly instead of failing
	// closed on the first contention.
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteStore{db: db}, nil
}

// Close releases the database.
func (s *SQLiteStore) Close() error { return s.db.Close() }

// Append records one event inside a transaction. The chain can
// never fork under concurrency.
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

// IdemGet returns one journal record. It returns false when none
// exists.
func (s *SQLiteStore) IdemGet(sessionID, key string) (IdempotencyRecord, bool, error) {
	row := s.db.QueryRow(`SELECT session_id, key, tool, args_hash, state, approval_id, status, content_type, body, body_too_large, resolution, note, created_at, updated_at FROM idempotency WHERE session_id = ? AND key = ?`, sessionID, key)
	rec, err := scanIdemRow(row)
	if err == sql.ErrNoRows {
		return IdempotencyRecord{}, false, nil
	}
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	return rec, true, nil
}

// IdemPut inserts or replaces one journal record.
func (s *SQLiteStore) IdemPut(rec IdempotencyRecord) error {
	_, err := s.db.Exec(`INSERT INTO idempotency (session_id, key, tool, args_hash, state, approval_id, status, content_type, body, body_too_large, resolution, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(session_id, key) DO UPDATE SET tool = excluded.tool, args_hash = excluded.args_hash, state = excluded.state, approval_id = excluded.approval_id, status = excluded.status, content_type = excluded.content_type, body = excluded.body, body_too_large = excluded.body_too_large, resolution = excluded.resolution, note = excluded.note, created_at = excluded.created_at, updated_at = excluded.updated_at`,
		rec.SessionID, rec.Key, rec.Tool, rec.ArgsHash, string(rec.State), rec.ApprovalID, rec.Status, rec.ContentType, rec.Body, boolToInt(rec.BodyTooLarge), rec.Resolution, rec.Note, rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}

// IdemClaim atomically claims a key for a new attempt inside one
// transaction. It inserts when absent. It replaces when the
// existing record never ran (discarded, or resolved-not-executed).
// Otherwise it returns the existing record and claimed=false.
func (s *SQLiteStore) IdemClaim(rec IdempotencyRecord) (IdempotencyRecord, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	defer tx.Rollback()
	row := tx.QueryRow(`SELECT session_id, key, tool, args_hash, state, approval_id, status, content_type, body, body_too_large, resolution, note, created_at, updated_at FROM idempotency WHERE session_id = ? AND key = ?`, rec.SessionID, rec.Key)
	existing, err := scanIdemRow(row)
	if err != nil && err != sql.ErrNoRows {
		return IdempotencyRecord{}, false, err
	}
	if err == nil && existing.State != IdemDiscarded &&
		!(existing.State == IdemResolved && existing.Resolution == "not-executed") {
		return existing, false, nil
	}
	if _, err := tx.Exec(`INSERT INTO idempotency (session_id, key, tool, args_hash, state, approval_id, status, content_type, body, body_too_large, resolution, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(session_id, key) DO UPDATE SET tool = excluded.tool, args_hash = excluded.args_hash, state = excluded.state, approval_id = excluded.approval_id, status = excluded.status, content_type = excluded.content_type, body = excluded.body, body_too_large = excluded.body_too_large, resolution = excluded.resolution, note = excluded.note, created_at = excluded.created_at, updated_at = excluded.updated_at`,
		rec.SessionID, rec.Key, rec.Tool, rec.ArgsHash, string(rec.State), rec.ApprovalID, rec.Status, rec.ContentType, rec.Body, boolToInt(rec.BodyTooLarge), rec.Resolution, rec.Note, rec.CreatedAt.UTC().Format(time.RFC3339Nano), rec.UpdatedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		return IdempotencyRecord{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return IdempotencyRecord{}, false, err
	}
	return rec, true, nil
}

// IdemList returns every journal record, oldest first.
func (s *SQLiteStore) IdemList() ([]IdempotencyRecord, error) {
	rows, err := s.db.Query(`SELECT session_id, key, tool, args_hash, state, approval_id, status, content_type, body, body_too_large, resolution, note, created_at, updated_at FROM idempotency ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdempotencyRecord
	for rows.Next() {
		rec, err := scanIdemRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// IdemPurgeBefore deletes records not updated since t.
func (s *SQLiteStore) IdemPurgeBefore(t time.Time) (int, error) {
	res, err := s.db.Exec(`DELETE FROM idempotency WHERE updated_at < ?`, t.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

func scanIdemRow(row interface{ Scan(dest ...any) error }) (IdempotencyRecord, error) {
	var rec IdempotencyRecord
	var state string
	var approvalID, contentType, resolution, note sql.NullString
	var status sql.NullInt64
	var body []byte
	var tooLarge int
	var created, updated string
	if err := row.Scan(&rec.SessionID, &rec.Key, &rec.Tool, &rec.ArgsHash, &state, &approvalID, &status, &contentType, &body, &tooLarge, &resolution, &note, &created, &updated); err != nil {
		return IdempotencyRecord{}, err
	}
	rec.State = IdempotencyState(state)
	rec.ApprovalID = approvalID.String
	if status.Valid {
		rec.Status = int(status.Int64)
	}
	rec.ContentType = contentType.String
	rec.Body = body
	rec.BodyTooLarge = tooLarge != 0
	rec.Resolution = resolution.String
	rec.Note = note.String
	var err error
	if rec.CreatedAt, err = time.Parse(time.RFC3339Nano, created); err != nil {
		return IdempotencyRecord{}, fmt.Errorf("bad created_at in idempotency row: %w", err)
	}
	if rec.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated); err != nil {
		return IdempotencyRecord{}, fmt.Errorf("bad updated_at in idempotency row: %w", err)
	}
	return rec, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ToolsBaselineGet returns the stored tool baseline. It returns
// false when none was ever established. One row holds the whole
// surface.
func (s *SQLiteStore) ToolsBaselineGet() (ToolsBaseline, bool, error) {
	row := s.db.QueryRow(`SELECT tools_json, hash, created_at, updated_at FROM tools_baseline WHERE id = 1`)
	var toolsJSON, hash, created, updated string
	if err := row.Scan(&toolsJSON, &hash, &created, &updated); err != nil {
		if err == sql.ErrNoRows {
			return ToolsBaseline{}, false, nil
		}
		return ToolsBaseline{}, false, err
	}
	var tools []BaselineTool
	if err := json.Unmarshal([]byte(toolsJSON), &tools); err != nil {
		return ToolsBaseline{}, false, fmt.Errorf("bad tools_baseline row: %w", err)
	}
	createdAt, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return ToolsBaseline{}, false, fmt.Errorf("bad created_at in tools_baseline row: %w", err)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return ToolsBaseline{}, false, fmt.Errorf("bad updated_at in tools_baseline row: %w", err)
	}
	return ToolsBaseline{Tools: tools, Hash: hash, CreatedAt: createdAt, UpdatedAt: updatedAt}, true, nil
}

// ToolsBaselinePut stores the baseline, replacing any previous one.
func (s *SQLiteStore) ToolsBaselinePut(b ToolsBaseline) error {
	toolsJSON, err := json.Marshal(b.Tools)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO tools_baseline (id, tools_json, hash, created_at, updated_at) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET tools_json = excluded.tools_json, hash = excluded.hash, created_at = excluded.created_at, updated_at = excluded.updated_at`,
		string(toolsJSON), b.Hash, b.CreatedAt.UTC().Format(time.RFC3339Nano), b.UpdatedAt.UTC().Format(time.RFC3339Nano))
	return err
}
