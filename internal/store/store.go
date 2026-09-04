// Package store persists the event stream to SQLite so provenance and
// timeline queries still work after the processes involved have exited.
// It is the only place that knows the on-disk schema; everything else in
// provctl talks to it through the typed methods below.
package store

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"github.com/thefoulowl/provctl/internal/model"
)

const schema = `
CREATE TABLE IF NOT EXISTS processes (
	pid         INTEGER NOT NULL,
	ppid        INTEGER NOT NULL DEFAULT 0,
	uid         INTEGER NOT NULL DEFAULT 0,
	gid         INTEGER NOT NULL DEFAULT 0,
	comm        TEXT NOT NULL DEFAULT '',
	exe_path    TEXT NOT NULL DEFAULT '',
	started_ns  INTEGER NOT NULL,
	exited_ns   INTEGER,
	exit_code   INTEGER,
	-- a pid can be recycled by the kernel; started_ns disambiguates
	-- successive lifetimes of the "same" numeric pid.
	PRIMARY KEY (pid, started_ns)
);
CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_ppid ON processes(ppid);

CREATE TABLE IF NOT EXISTS file_events (
	id   INTEGER PRIMARY KEY AUTOINCREMENT,
	pid  INTEGER NOT NULL,
	path TEXT NOT NULL,
	ts_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_file_events_path ON file_events(path);
CREATE INDEX IF NOT EXISTS idx_file_events_pid ON file_events(pid);

CREATE TABLE IF NOT EXISTS net_events (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	pid      INTEGER NOT NULL,
	dst_ip   TEXT NOT NULL,
	dst_port INTEGER NOT NULL,
	ts_ns    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_net_events_pid ON net_events(pid);

-- One row per live-observed event (not the /proc startup backfill — see
-- Seed vs Apply below), rendered text and all, so "provctl top" can tail
-- it with a plain id-ordered poll instead of re-deriving a feed from the
-- other tables' mutable state.
CREATE TABLE IF NOT EXISTS activity_log (
	id    INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ns INTEGER NOT NULL,
	kind  TEXT NOT NULL,
	pid   INTEGER NOT NULL,
	text  TEXT NOT NULL
);
`

// Store wraps a SQLite database holding the durable event history.
type Store struct {
	db *sql.DB
}

// Open creates (if needed) and opens the SQLite database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	db.SetMaxOpenConns(1) // modernc.org/sqlite: keep writes serialized

	// WAL + NORMAL sync: readers (trace/timeline/ps, run from a separate
	// process) don't block the writer, and a single fsync now covers a
	// whole batch instead of every individual event. `watch` runs against
	// a live, bursty stream (a single exec can produce dozens of file
	// opens in the same millisecond — observed in practice) where
	// per-event fsync would otherwise be the bottleneck.
	for _, pragma := range []string{`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL`} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("store: %s: %w", pragma, err)
		}
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// execer is satisfied by both *sql.DB and *sql.Tx, letting apply() run
// either standalone (Apply) or as part of a larger transaction (ApplyBatch).
type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// Apply persists one live-observed event in its own transaction, including
// an activity_log entry for `provctl top`. Prefer ApplyBatch when applying
// many events at once (e.g. draining a channel).
func (s *Store) Apply(e model.Event) error {
	return apply(s.db, e)
}

// ApplyBatch persists many live-observed events as a single transaction,
// so a burst of events costs one fsync instead of one per event.
func (s *Store) ApplyBatch(events []model.Event) error {
	return runBatch(s.db, events, apply)
}

// Seed persists events representing already-known state rather than
// live-observed activity — specifically, the /proc snapshot `watch` takes
// at startup so pre-existing processes have a name. Unlike Apply/ApplyBatch,
// this does not write to activity_log: those synthetic "exec" events aren't
// something that just happened, and logging all of them would flood
// `provctl top`'s live feed with hundreds of entries every time watch starts.
func (s *Store) Seed(events []model.Event) error {
	return runBatch(s.db, events, applyCore)
}

func runBatch(db *sql.DB, events []model.Event, applyFn func(execer, model.Event) error) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin batch: %w", err)
	}
	for _, e := range events {
		if err := applyFn(tx, e); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// apply persists one event's effect on the derived tables (via applyCore)
// and, since this path is for live-observed activity, appends it to
// activity_log for provctl top.
func apply(q execer, e model.Event) error {
	if err := applyCore(q, e); err != nil {
		return err
	}
	_, err := q.Exec(
		`INSERT INTO activity_log (ts_ns, kind, pid, text) VALUES (?, ?, ?, ?)`,
		e.Time.UnixNano(), e.Type.String(), e.PID, e.Describe(),
	)
	return err
}

func applyCore(q execer, e model.Event) error {
	ts := e.Time.UnixNano()
	switch e.Type {
	case model.TypeFork:
		_, err := q.Exec(
			`INSERT INTO processes (pid, ppid, comm, started_ns) VALUES (?, ?, ?, ?)
			 ON CONFLICT (pid, started_ns) DO UPDATE SET ppid=excluded.ppid, comm=excluded.comm`,
			e.PID, e.PPID, e.Comm, ts,
		)
		return err

	case model.TypeExec:
		// A fork typically preceded this with the same pid and an earlier
		// (or equal) started_ns; find that open lifetime row and enrich it
		// rather than creating a second row for the same process.
		//
		// Scoped to the *most recent* open lifetime, not every open row
		// for this pid: if an exit event was ever missed (a full ring
		// buffer drops events) that stale row stays open forever, and once
		// the kernel recycles the pid an unscoped UPDATE would rewrite the
		// old process's identity with this new binary's — silently
		// misattributing everything the old process did.
		res, err := q.Exec(
			`UPDATE processes SET ppid=?, uid=?, gid=?, comm=?, exe_path=?
			 WHERE pid=? AND started_ns = (
			     SELECT MAX(started_ns) FROM processes WHERE pid=? AND exited_ns IS NULL
			 )`,
			e.PPID, e.UID, e.GID, e.Comm, e.Filename, e.PID, e.PID,
		)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			_, err = q.Exec(
				`INSERT INTO processes (pid, ppid, uid, gid, comm, exe_path, started_ns)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				e.PID, e.PPID, e.UID, e.GID, e.Comm, e.Filename, ts,
			)
		}
		return err

	case model.TypeExit:
		// Same scoping rationale as EXEC above: close only the newest open
		// lifetime, so a recycled pid can't retroactively close a stale row.
		_, err := q.Exec(
			`UPDATE processes SET exited_ns=?, exit_code=?
			 WHERE pid=? AND started_ns = (
			     SELECT MAX(started_ns) FROM processes WHERE pid=? AND exited_ns IS NULL
			 )`,
			ts, e.ExitCode, e.PID, e.PID,
		)
		return err

	case model.TypeFileOpen:
		_, err := q.Exec(
			`INSERT INTO file_events (pid, path, ts_ns) VALUES (?, ?, ?)`,
			e.PID, e.Filename, ts,
		)
		return err

	case model.TypeConnect:
		ip := ""
		if e.DstIP != nil {
			ip = e.DstIP.String()
		}
		_, err := q.Exec(
			`INSERT INTO net_events (pid, dst_ip, dst_port, ts_ns) VALUES (?, ?, ?, ?)`,
			e.PID, ip, e.DstPort, ts,
		)
		return err
	}
	return nil
}

// Process is a stored process lifetime row.
type Process struct {
	PID       uint32
	PPID      uint32
	UID, GID  uint32
	Comm      string
	ExePath   string
	StartedAt time.Time
	ExitedAt  *time.Time
	ExitCode  *int
}

// LatestProcess returns the most recently started lifetime for pid.
func (s *Store) LatestProcess(pid uint32) (*Process, error) {
	row := s.db.QueryRow(
		`SELECT pid, ppid, uid, gid, comm, exe_path, started_ns, exited_ns, exit_code
		 FROM processes WHERE pid=? ORDER BY started_ns DESC LIMIT 1`, pid)
	return scanProcess(row)
}

func scanProcess(row *sql.Row) (*Process, error) {
	var p Process
	var startedNs int64
	var exitedNs sql.NullInt64
	var exitCode sql.NullInt64
	if err := row.Scan(&p.PID, &p.PPID, &p.UID, &p.GID, &p.Comm, &p.ExePath, &startedNs, &exitedNs, &exitCode); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	p.StartedAt = time.Unix(0, startedNs)
	if exitedNs.Valid {
		t := time.Unix(0, exitedNs.Int64)
		p.ExitedAt = &t
	}
	if exitCode.Valid {
		c := int(exitCode.Int64)
		p.ExitCode = &c
	}
	return &p, nil
}

// Ancestors walks the parent chain starting at pid, closest first.
func (s *Store) Ancestors(pid uint32, maxDepth int) ([]Process, error) {
	var chain []Process
	seen := map[uint32]bool{}
	cur := pid
	for i := 0; i < maxDepth; i++ {
		if seen[cur] || cur == 0 {
			break
		}
		seen[cur] = true
		p, err := s.LatestProcess(cur)
		if err != nil {
			return nil, err
		}
		if p == nil {
			break
		}
		chain = append(chain, *p)
		cur = p.PPID
	}
	return chain, nil
}

// ProcessAt returns the lifetime of pid that was active at the given
// instant (started at or before it, and not yet exited by it).
func (s *Store) ProcessAt(pid uint32, at time.Time) (*Process, error) {
	row := s.db.QueryRow(
		`SELECT pid, ppid, uid, gid, comm, exe_path, started_ns, exited_ns, exit_code
		 FROM processes WHERE pid=? AND started_ns<=? AND (exited_ns IS NULL OR exited_ns>=?)
		 ORDER BY started_ns DESC LIMIT 1`, pid, at.UnixNano(), at.UnixNano())
	return scanProcess(row)
}

// AllProcesses returns every recorded process lifetime, oldest first. When
// liveOnly is true, only lifetimes that have not recorded an exit are
// included.
func (s *Store) AllProcesses(liveOnly bool) ([]Process, error) {
	q := `SELECT pid, ppid, uid, gid, comm, exe_path, started_ns, exited_ns, exit_code FROM processes`
	if liveOnly {
		q += ` WHERE exited_ns IS NULL`
	}
	q += ` ORDER BY started_ns ASC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProcesses(rows)
}

// Children returns processes whose ppid is pid, oldest first.
func (s *Store) Children(pid uint32) ([]Process, error) {
	rows, err := s.db.Query(
		`SELECT pid, ppid, uid, gid, comm, exe_path, started_ns, exited_ns, exit_code
		 FROM processes WHERE ppid=? ORDER BY started_ns ASC`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProcesses(rows)
}

func scanProcesses(rows *sql.Rows) ([]Process, error) {
	var out []Process
	for rows.Next() {
		var p Process
		var startedNs int64
		var exitedNs, exitCode sql.NullInt64
		if err := rows.Scan(&p.PID, &p.PPID, &p.UID, &p.GID, &p.Comm, &p.ExePath, &startedNs, &exitedNs, &exitCode); err != nil {
			return nil, err
		}
		p.StartedAt = time.Unix(0, startedNs)
		if exitedNs.Valid {
			t := time.Unix(0, exitedNs.Int64)
			p.ExitedAt = &t
		}
		if exitCode.Valid {
			c := int(exitCode.Int64)
			p.ExitCode = &c
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// FileEvent is one recorded open of a path.
type FileEvent struct {
	PID  uint32
	Path string
	At   time.Time
}

// FileEventsForPath returns every recorded open of an exact path, oldest first.
func (s *Store) FileEventsForPath(path string) ([]FileEvent, error) {
	rows, err := s.db.Query(`SELECT pid, path, ts_ns FROM file_events WHERE path=? ORDER BY ts_ns ASC`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileEvent
	for rows.Next() {
		var fe FileEvent
		var ts int64
		if err := rows.Scan(&fe.PID, &fe.Path, &ts); err != nil {
			return nil, err
		}
		fe.At = time.Unix(0, ts)
		out = append(out, fe)
	}
	return out, rows.Err()
}

// ExecEventsForPath returns processes list whose exe_path matches path,
// i.e. every time this file was executed, oldest first.
func (s *Store) ExecEventsForPath(path string) ([]Process, error) {
	rows, err := s.db.Query(
		`SELECT pid, ppid, uid, gid, comm, exe_path, started_ns, exited_ns, exit_code
		 FROM processes WHERE exe_path=? ORDER BY started_ns ASC`, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProcesses(rows)
}

// NetEvent is one recorded outbound connection attempt.
type NetEvent struct {
	PID     uint32
	DstIP   string
	DstPort uint16
	At      time.Time
}

// NetEventsForPID returns every recorded connection made by pid, oldest first.
func (s *Store) NetEventsForPID(pid uint32) ([]NetEvent, error) {
	rows, err := s.db.Query(`SELECT pid, dst_ip, dst_port, ts_ns FROM net_events WHERE pid=? ORDER BY ts_ns ASC`, pid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NetEvent
	for rows.Next() {
		var ne NetEvent
		var ts int64
		if err := rows.Scan(&ne.PID, &ne.DstIP, &ne.DstPort, &ts); err != nil {
			return nil, err
		}
		ne.At = time.Unix(0, ts)
		out = append(out, ne)
	}
	return out, rows.Err()
}

// NetEventBefore returns the most recent connection made by pid at or
// before the given time, within window — used to guess "this file was
// probably downloaded from this connection".
func (s *Store) NetEventBefore(pid uint32, before time.Time, window time.Duration) (*NetEvent, error) {
	row := s.db.QueryRow(
		`SELECT pid, dst_ip, dst_port, ts_ns FROM net_events
		 WHERE pid=? AND ts_ns <= ? AND ts_ns >= ?
		 ORDER BY ts_ns DESC LIMIT 1`,
		pid, before.UnixNano(), before.Add(-window).UnixNano(),
	)
	var ne NetEvent
	var ts int64
	if err := row.Scan(&ne.PID, &ne.DstIP, &ne.DstPort, &ts); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	ne.At = time.Unix(0, ts)
	return &ne, nil
}

// TimelineEntry is one line in a process's flight-recorder timeline.
type TimelineEntry struct {
	At   time.Time
	Kind string // "started" | "opened" | "connected" | "spawned" | "exited"
	Text string
}

// Timeline reconstructs the full recorded life of a pid: its own
// start/exit, every file it opened, every connection it made, and every
// child it spawned — merged and sorted by time.
func (s *Store) Timeline(pid uint32) ([]TimelineEntry, error) {
	p, err := s.LatestProcess(pid)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("store: no recorded process with pid %d", pid)
	}

	var out []TimelineEntry
	out = append(out, TimelineEntry{At: p.StartedAt, Kind: "started",
		Text: fmt.Sprintf("started (%s, ppid %d)", p.Comm, p.PPID)})

	files, err := s.db.Query(`SELECT path, ts_ns FROM file_events WHERE pid=? ORDER BY ts_ns ASC`, pid)
	if err != nil {
		return nil, err
	}
	for files.Next() {
		var path string
		var ts int64
		if err := files.Scan(&path, &ts); err != nil {
			files.Close()
			return nil, err
		}
		out = append(out, TimelineEntry{At: time.Unix(0, ts), Kind: "opened", Text: "opened " + path})
	}
	files.Close()

	nets, err := s.db.Query(`SELECT dst_ip, dst_port, ts_ns FROM net_events WHERE pid=? ORDER BY ts_ns ASC`, pid)
	if err != nil {
		return nil, err
	}
	for nets.Next() {
		var ip string
		var port uint16
		var ts int64
		if err := nets.Scan(&ip, &port, &ts); err != nil {
			nets.Close()
			return nil, err
		}
		out = append(out, TimelineEntry{At: time.Unix(0, ts), Kind: "connected",
			Text: fmt.Sprintf("connected to %s:%d", ip, port)})
	}
	nets.Close()

	children, err := s.Children(pid)
	if err != nil {
		return nil, err
	}
	for _, c := range children {
		out = append(out, TimelineEntry{At: c.StartedAt, Kind: "spawned",
			Text: fmt.Sprintf("spawned child %d (%s)", c.PID, c.Comm)})
	}

	if p.ExitedAt != nil {
		code := 0
		if p.ExitCode != nil {
			code = *p.ExitCode
		}
		out = append(out, TimelineEntry{At: *p.ExitedAt, Kind: "exited",
			Text: fmt.Sprintf("exited (code %d)", code)})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}
