package store

import "time"

// ActivityEntry is one row of the live event feed `provctl top` tails.
type ActivityEntry struct {
	ID   int64
	At   time.Time
	Kind string
	PID  uint32
	Text string
}

// RecentActivity returns the most recent limit entries, oldest first (so
// callers can print/append them directly as a scrolling log). Intended for
// an initial screen fill when a viewer like `top` starts up.
func (s *Store) RecentActivity(limit int) ([]ActivityEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts_ns, kind, pid, text FROM activity_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries, err := scanActivity(rows)
	if err != nil {
		return nil, err
	}
	// reverse: query was newest-first (so LIMIT keeps the *most* recent
	// rows), but callers want oldest-first for display.
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	return entries, nil
}

// ActivityAfter returns entries with id > afterID, oldest first, capped at
// limit. Pass the ID of the last entry you've already seen — 0 to start
// from the beginning — to poll for what's new since then.
func (s *Store) ActivityAfter(afterID int64, limit int) ([]ActivityEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, ts_ns, kind, pid, text FROM activity_log WHERE id > ? ORDER BY id ASC LIMIT ?`,
		afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanActivity(rows)
}

func scanActivity(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}) ([]ActivityEntry, error) {
	var out []ActivityEntry
	for rows.Next() {
		var e ActivityEntry
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.PID, &e.Text); err != nil {
			return nil, err
		}
		e.At = time.Unix(0, ts)
		out = append(out, e)
	}
	return out, rows.Err()
}
