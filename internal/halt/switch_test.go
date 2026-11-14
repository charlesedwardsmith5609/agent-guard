package halt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestInterpret(t *testing.T) {
	cases := []struct {
		in      string
		err     error
		halted  bool
		wantWhy string
	}{
		{"running\n", nil, false, "running"},
		{"  RUN  ", nil, false, "running"},
		{"0", nil, false, "running"},
		{"halted", nil, true, "halted"},
		{"halt", nil, true, "halted"},
		{"1\n", nil, true, "halted"},
		{"", nil, true, "corrupt"},
		{"maybe", nil, true, "corrupt"},
		{"", os.ErrNotExist, true, "cannot be read"},
		{"", errCorrupt, true, "corrupt"},
	}
	for _, tc := range cases {
		halted, why := interpret(tc.in, tc.err)
		if halted != tc.halted || !strings.Contains(why, tc.wantWhy) {
			t.Errorf("interpret(%q, %v) = %v %q", tc.in, tc.err, halted, why)
		}
	}
}

// commit runs Check and commits any proposed transition, as the proxy does after
// its audit record succeeds.
func commit(t *testing.T, s *Switch) Result {
	t.Helper()
	r := s.Check()
	if r.Transition != "" && !s.Commit(r) {
		t.Fatalf("commit of %q rejected", r.Transition)
	}
	return r
}

func TestCheckFailClosedAndTransitions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "halt")
	s := New(path)

	r := commit(t, s)
	if !r.Halted || r.Transition != "halt" || !strings.Contains(r.Reason, "cannot be read") {
		t.Fatalf("missing file: %+v", r)
	}
	r = commit(t, s)
	if !r.Halted || r.Transition != "" {
		t.Fatalf("second missing read should not repeat the transition: %+v", r)
	}

	if err := os.WriteFile(path, []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = commit(t, s)
	if r.Halted || r.Transition != "resume" || !strings.Contains(r.Reason, "running") {
		t.Fatalf("resume: %+v", r)
	}

	if err := os.WriteFile(path, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	r = commit(t, s)
	if !r.Halted || r.Transition != "halt" || !strings.Contains(r.Reason, "corrupt") {
		t.Fatalf("corrupt: %+v", r)
	}

	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	r = commit(t, New(path+".link"))
	if !r.Halted || r.Transition != "halt" || !strings.Contains(r.Reason, "corrupt") {
		t.Fatalf("symlink: %+v", r)
	}
}

func TestFirstRunningReadCommitsWithoutTransition(t *testing.T) {
	path := filepath.Join(t.TempDir(), "halt")
	if err := os.WriteFile(path, []byte("running"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(path)
	if r := s.Check(); r.Halted || r.Transition != "" {
		t.Fatalf("first running read: %+v", r)
	}
	if r := s.Check(); r.Halted || r.Transition != "" {
		t.Fatalf("second running read: %+v", r)
	}
}

// within runs f and fails the test if it does not return before the deadline.
func within(t *testing.T, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); f() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

func TestUnsafeControlFilesFailClosed(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	zero := filepath.Join(dir, "zero")
	if err := os.Symlink("/dev/zero", zero); err != nil {
		t.Fatal(err)
	}
	subdir := filepath.Join(dir, "dir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, []byte(strings.Repeat("running\n", 20)), 0o600); err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(dir, "exact") // 64 bytes of padding around a valid token is still corrupt text
	if err := os.WriteFile(exact, []byte("running"+strings.Repeat(" ", 57)), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"fifo": fifo, "dev-zero symlink": zero, "directory": subdir, "over 64 bytes": big} {
		t.Run(name, func(t *testing.T) {
			var r Result
			within(t, "Check", func() { r = New(path).Check() })
			if !r.Halted || r.Transition != "halt" || !strings.Contains(r.Reason, "corrupt") {
				t.Fatalf("got %+v", r)
			}
		})
	}
	t.Run("exactly 64 bytes is accepted", func(t *testing.T) {
		var r Result
		within(t, "Check", func() { r = New(exact).Check() })
		if r.Halted {
			t.Fatalf("got %+v", r)
		}
	})
}

// gatedReader returns scripted contents. The first call blocks on gate after it has
// captured its answer, so a test can hold one observation in flight.
type gatedReader struct {
	mu      sync.Mutex
	content string
	calls   int
	entered chan struct{}
	gate    chan struct{}
}

func newGatedReader(content string) *gatedReader {
	return &gatedReader{content: content, entered: make(chan struct{}), gate: make(chan struct{})}
}

func (g *gatedReader) set(c string) { g.mu.Lock(); g.content = c; g.mu.Unlock() }

func (g *gatedReader) read(string) (string, error) {
	g.mu.Lock()
	g.calls++
	first := g.calls == 1
	c := g.content
	g.mu.Unlock()
	if first {
		close(g.entered)
		<-g.gate
	}
	return c, nil
}

func waitFor(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func TestReadHappensOutsideMutex(t *testing.T) {
	g := newGatedReader("running")
	s := New("unused")
	s.read = g.read
	got := make(chan Result, 1)
	go func() { got <- s.Check() }()
	waitFor(t, g.entered, "first read to start")
	// The first Check is parked inside the reader. If it held mu, this would hang.
	var r Result
	within(t, "second Check", func() { r = s.Check() })
	if r.Halted {
		t.Fatalf("second check: %+v", r)
	}
	close(g.gate)
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("first Check did not finish")
	}
}

// A caller that read "running" must not resume over a halt another caller committed
// while it was reading.
func TestStaleObservationIsNotApplied(t *testing.T) {
	g := newGatedReader("running")
	s := New("unused")
	s.read = g.read
	got := make(chan Result, 1)
	go func() { got <- s.Check() }() // A observes "running" and parks
	waitFor(t, g.entered, "A's read")

	g.set("halted")
	r := commit(t, s) // B observes halted and commits it
	if !r.Halted || r.Transition != "halt" {
		t.Fatalf("B: %+v", r)
	}
	close(g.gate)
	var a Result
	select {
	case a = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("A did not finish")
	}
	if !a.Halted || a.Transition != "" {
		t.Fatalf("A applied a stale resume: %+v", a)
	}
	if r := s.Check(); !r.Halted {
		t.Fatalf("state was resumed: %+v", r)
	}
}

func TestAbortRetriesAndProposalExcludesOthers(t *testing.T) {
	var mu sync.Mutex
	content := "halted"
	s := New("unused")
	s.read = func(string) (string, error) { mu.Lock(); defer mu.Unlock(); return content, nil }
	set := func(c string) { mu.Lock(); content = c; mu.Unlock() }

	commit(t, s) // committed: halted
	set("running")

	r := s.Check()
	if r.Transition != "resume" || r.Halted {
		t.Fatalf("proposal: %+v", r)
	}
	if o := s.Check(); !o.Halted || o.Transition != "" || o.Reason != reasonBusy {
		t.Fatalf("another caller during a proposal: %+v", o)
	}
	s.Abort(r) // the audit write failed
	if s.Commit(r) {
		t.Fatal("an aborted proposal must not commit")
	}
	r2 := s.Check()
	if r2.Transition != "resume" {
		t.Fatalf("an aborted transition must be proposed again: %+v", r2)
	}
	if !s.Commit(r2) {
		t.Fatal("commit rejected")
	}
	if s.Commit(r2) {
		t.Fatal("a proposal commits once")
	}
	if r := s.Check(); r.Halted || r.Transition != "" {
		t.Fatalf("after commit: %+v", r)
	}
}

func TestMissingFileIsNotExist(t *testing.T) {
	_, err := readControl(filepath.Join(t.TempDir(), "nope"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}
