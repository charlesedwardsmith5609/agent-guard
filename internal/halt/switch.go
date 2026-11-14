// Package halt owns the proxy's halt state.
//
// The control is a small text file. One mutex owns interpretation of that file
// and the last state derived from it. Nothing else stores a halt flag.
package halt

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"
)

const maxControlBytes = 64

// Switch is the only owner of halt state. mu guards known, halted, gen and pending.
// Callers must not keep a halt flag of their own; they call Check and, when it
// reports a transition, record it and then Commit (or Abort). File I/O happens
// outside mu.
type Switch struct {
	mu      sync.Mutex
	path    string
	read    func(path string) (string, error) // control reader; tests replace it
	known   bool
	halted  bool
	gen     uint64    // incremented on every commit
	pending *proposal // the one transition awaiting its audit record
}

type proposal struct {
	gen    uint64
	halted bool
}

// Result is what one Check found.
type Result struct {
	// Halted reports whether this call must be refused. For a transition it is the
	// proposed state, which holds only if the caller then records and commits.
	Halted bool
	// Transition is "halt", "resume", or "" when the state did not change.
	Transition string
	Reason     string
	p          *proposal
}

const (
	reasonBusy  = "halt transition is being recorded; failing closed"
	reasonStale = "halt control changed while being read; failing closed"
)

// maxStaleRetries bounds how often one Check re-reads after another caller committed.
const maxStaleRetries = 3

// New returns a switch for path. The state starts unknown and is treated as
// halted until a read says otherwise, so a missing file fails closed.
func New(path string) *Switch {
	return &Switch{path: path, halted: true, read: readControl}
}

// Check reads the control file and reports whether calls must be refused.
//
// A change of state is only proposed. The caller must write the audit record and
// call Commit; until then the committed state is unchanged, so a transition whose
// record failed is proposed again by the next Check. While a proposal is
// outstanding every other caller is refused. If the caller cannot commit it must
// call Abort. The first Check that finds the proxy halted proposes "halt"; the
// first that finds it running commits at once and reports no transition.
//
// A missing file, a read error, a symlink, a non-regular file, or contents other
// than the documented tokens are halted. Reason says which.
func (s *Switch) Check() Result {
	for try := 0; try < maxStaleRetries; try++ {
		s.mu.Lock()
		gen := s.gen
		s.mu.Unlock()

		next, why := interpret(s.read(s.path)) // I/O outside the mutex

		s.mu.Lock()
		if s.gen != gen {
			s.mu.Unlock()
			continue // another caller committed after we started reading
		}
		r := s.decideLocked(next, why)
		s.mu.Unlock()
		return r
	}
	return Result{Halted: true, Reason: reasonStale}
}

func (s *Switch) decideLocked(next bool, why string) Result {
	if s.pending != nil {
		return Result{Halted: true, Reason: reasonBusy}
	}
	if !s.known && !next {
		s.known, s.halted = true, false
		s.gen++
		return Result{Halted: false, Reason: why}
	}
	if s.known && next == s.halted {
		return Result{Halted: s.halted, Reason: why}
	}
	trans := "resume"
	if next {
		trans = "halt"
	}
	p := &proposal{gen: s.gen, halted: next}
	s.pending = p
	return Result{Halted: next, Transition: trans, Reason: why, p: p}
}

// Commit makes a proposed transition take effect. It reports false if r holds no
// outstanding proposal.
func (s *Switch) Commit(r Result) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.p == nil || s.pending != r.p || s.gen != r.p.gen {
		return false
	}
	s.known, s.halted = true, r.p.halted
	s.pending = nil
	s.gen++
	return true
}

// Abort releases a proposal that could not be recorded. The committed state is
// unchanged, so the next Check proposes the transition again.
func (s *Switch) Abort(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.p != nil && s.pending == r.p {
		s.pending = nil
	}
}

func interpret(text string, err error) (halted bool, reason string) {
	if err != nil {
		if errors.Is(err, errCorrupt) {
			return true, "halt control is corrupt; failing closed"
		}
		return true, "halt control cannot be read; failing closed"
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "running", "run", "0":
		return false, "halt control is running"
	case "halted", "halt", "1":
		return true, "halt control is halted"
	default:
		return true, "halt control is corrupt; failing closed"
	}
}

var errCorrupt = errors.New("halt: corrupt control")

// readControl opens the file once without following a symlink and without
// blocking on a FIFO, requires a regular file of at most maxControlBytes, and reads
// through a limit. Anything else is corrupt.
func readControl(path string) (string, error) {
	if !safeOpenSupported {
		return "", errors.New("halt: safe open is not supported on this platform")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|noFollow|nonBlock, 0)
	if err != nil {
		if isLoop(errors.Unwrap(err)) {
			return "", errCorrupt // a symlink
		}
		return "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxControlBytes {
		return "", errCorrupt
	}
	b, err := io.ReadAll(io.LimitReader(f, maxControlBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxControlBytes {
		return "", errCorrupt
	}
	return string(b), nil
}
