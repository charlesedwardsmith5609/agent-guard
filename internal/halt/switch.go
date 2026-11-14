// Package halt owns the proxy's halt state.
//
// The control is a small text file. One mutex owns interpretation of that file
// and the last state derived from it. Nothing else stores a halt flag.
package halt

import (
	"errors"
	"os"
	"strings"
	"sync"
)

const maxControlBytes = 64

// Switch is the only owner of halt state. mu guards known and halted. Callers
// must not keep a halt flag of their own; they call Read.
type Switch struct {
	mu     sync.Mutex
	path   string
	known  bool
	halted bool
}

// New returns a switch for path. The state starts unknown and is treated as
// halted until a read says otherwise, so a missing file fails closed.
func New(path string) *Switch {
	return &Switch{path: path, halted: true}
}

// Read reads the control file and reports whether calls must be refused.
// transition is "halt", "resume", or "" when the state did not change.
// The first read that finds the proxy halted reports transition "halt".
// The first read that finds it running reports no transition.
//
// A missing file, a read error, a symlink, a non-regular file, or contents
// other than the documented tokens are halted. reason explains which.
func (s *Switch) Read() (halted bool, transition, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, why := interpret(readControl(s.path))
	if !s.known {
		s.known = true
		s.halted = next
		if next {
			return true, "halt", why
		}
		return false, "", why
	}
	if next == s.halted {
		return s.halted, "", why
	}
	s.halted = next
	if next {
		return true, "halt", why
	}
	return false, "resume", why
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

func readControl(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.Mode().IsRegular() || fi.Size() > maxControlBytes {
		return "", errCorrupt
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(b) > maxControlBytes {
		return "", errCorrupt
	}
	return string(b), nil
}
