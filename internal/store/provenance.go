package store

import (
	"fmt"
	"time"
)

// downloadWindow bounds how far back before a file first appears we'll
// look for a connection to credit as its likely source.
const downloadWindow = 2 * time.Minute

// ProvenanceHop is one step in a file's reconstructed history. Depth 0 is
// the main chain (who created it, who reopened it, who executed it); depth
// 1 is a detail nested under the preceding depth-0 execution hop (what that
// run did next). Rendering indentation is a CLI concern, not this package's.
type ProvenanceHop struct {
	At    time.Time
	Text  string
	Depth int
}

func actorLabel(p *Process, pid uint32) string {
	if p == nil {
		return fmt.Sprintf("pid %d", pid)
	}
	return fmt.Sprintf("%s (pid %d)", p.Comm, p.PID)
}

// Provenance reconstructs what we can prove about a path from the recorded
// event history: who first touched it, what that process was doing right
// before (a strong signal for "where did this come from"), who reopened it
// afterward, and — if it was ever executed — what the resulting process did.
//
// This is a best-effort heuristic over path-string matches, not a proof:
// v1 does not track inode identity across renames/moves, so a file copied
// or extracted under a new name shows up as an unrelated path rather than
// a continuation of this chain.
func (s *Store) Provenance(path string) ([]ProvenanceHop, error) {
	fileEvents, err := s.FileEventsForPath(path)
	if err != nil {
		return nil, err
	}
	if len(fileEvents) == 0 {
		return nil, fmt.Errorf("store: no recorded activity for path %q", path)
	}

	var hops []ProvenanceHop
	first := fileEvents[0]

	firstProc, err := s.ProcessAt(first.PID, first.At)
	if err != nil {
		return nil, err
	}
	if firstProc != nil {
		hops = append(hops, ProvenanceHop{At: firstProc.StartedAt, Text: actorLabel(firstProc, first.PID)})

		if net, err := s.NetEventBefore(first.PID, first.At, downloadWindow); err != nil {
			return nil, err
		} else if net != nil {
			hops = append(hops, ProvenanceHop{At: net.At,
				Text: fmt.Sprintf("connected to %s:%d", net.DstIP, net.DstPort)})
		}
	}
	hops = append(hops, ProvenanceHop{At: first.At, Text: fmt.Sprintf("opened %s", path)})

	// Later opens of the same path by other processes: copies, extraction,
	// antivirus scans, or a shell about to exec it.
	for _, fe := range fileEvents[1:] {
		if fe.PID == first.PID {
			continue
		}
		p, err := s.ProcessAt(fe.PID, fe.At)
		if err != nil {
			return nil, err
		}
		hops = append(hops, ProvenanceHop{At: fe.At, Text: fmt.Sprintf("opened by %s", actorLabel(p, fe.PID))})
	}

	// Every time this path was executed, plus what that run did next.
	execs, err := s.ExecEventsForPath(path)
	if err != nil {
		return nil, err
	}
	for _, ex := range execs {
		hops = append(hops, ProvenanceHop{At: ex.StartedAt,
			Text: fmt.Sprintf("executed as %s", actorLabel(&ex, ex.PID))})

		nets, err := s.NetEventsForPID(ex.PID)
		if err != nil {
			return nil, err
		}
		for _, n := range nets {
			hops = append(hops, ProvenanceHop{At: n.At, Depth: 1,
				Text: fmt.Sprintf("connected to %s:%d", n.DstIP, n.DstPort)})
		}

		children, err := s.Children(ex.PID)
		if err != nil {
			return nil, err
		}
		for _, c := range children {
			hops = append(hops, ProvenanceHop{At: c.StartedAt, Depth: 1,
				Text: fmt.Sprintf("spawned %s", actorLabel(&c, c.PID))})
		}
	}

	return hops, nil
}
