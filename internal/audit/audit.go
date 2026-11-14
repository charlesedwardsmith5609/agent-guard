// Package audit writes one JSON line per tool-call decision.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"agent-guard/internal/policy"
)

const (
	defaultQueue = 4096
	previewMax   = 256
	reasonMax    = 200
)

// Record is one audit line. It never contains headers, API keys or full bodies.
type Record struct {
	Time        time.Time `json:"ts"`
	Tool        string    `json:"tool"`
	ToolUseID   string    `json:"tool_use_id"`
	Decision    string    `json:"decision"`
	Rule        string    `json:"rule"`
	Reason      string    `json:"reason"`
	ArgsSHA256  string    `json:"args_sha256"`
	ArgsPreview string    `json:"args_preview,omitempty"`
	LatencyMS   float64   `json:"latency_ms"`
	Stream      bool      `json:"stream"`
	// Profile is the policy profile that applied. Empty when the call was
	// refused before a profile could be selected.
	Profile string `json:"profile"`
	// Agent is the redacted agent identity, when the request carried one.
	Agent string `json:"agent,omitempty"`
	// Event is set for halt-control lines ("halt", "resume") and for a tool
	// call refused because the proxy is halted ("refusal"). Ordinary decisions
	// omit it.
	Event string `json:"event,omitempty"`
}

// RedactID makes an untrusted identifier (tool name, tool_use id) safe to record or export:
// restricted to a small alphabet, then stripped of credential-shaped text.
func RedactID(s string) string { return redactString(policy.SafeID(s)) }

// Options configures a Logger.
type Options struct {
	QueueSize int      // records buffered before Observe starts failing (default 4096)
	NoPreview bool     // record only the argument hash
	Canaries  []string // opaque policy canaries; redacted from previews and reasons (copied)
}

var (
	errClosed = errors.New("audit: logger is closed")
	errFailed = errors.New("audit: writer has failed")
	errFull   = errors.New("audit: queue is full")
)

// Claim states of an item. The writer claims a record before writing it; a caller whose context
// expires first cancels it instead, so a record the proxy has given up on is never written.
const (
	itemQueued int32 = iota
	itemClaimed
	itemCancelled
)

// claimGrace is how long a caller whose context expired waits for a write that has already
// started, so the log and the proxy's final decision agree.
var claimGrace = 2 * time.Second

// item is one queued record with the channel the writer answers on.
type item struct {
	rec   Record
	ack   chan error // capacity 1: the writer never blocks on it
	state atomic.Int32
}

// Logger implements policy.Observer.
//
// Ownership: one writer goroutine owns the destination and the encoder. Other goroutines send
// items on queue with a non-blocking send and then wait, bounded by their context, for the
// writer's answer, so Observe returns nil only after the record was written. The RWMutex guards
// just the closed flag and the close of queue: Observe holds the read lock across its send and
// Close takes the write lock before closing the channel, so no send can race the close.
type Logger struct {
	opt    Options
	out    io.Writer
	closer io.Closer

	mu     sync.RWMutex
	closed bool
	queue  chan *item

	failed    atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Open appends to path. New files are created exclusively with mode 0600; existing files are
// opened without following symlinks or blocking on FIFOs. Either way the opened file must be a
// regular file that is not accessible to group or others (permissions on a file the logger did
// not create are never changed).
func Open(path string, opt Options) (*Logger, error) {
	if !safeOpenSupported {
		return nil, errors.New("audit: opening the log without following symlinks is only supported on Unix")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND|noFollow|nonBlock, 0)
	}
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("audit: %s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("audit: %s has mode %o; want 0600", path, fi.Mode().Perm())
	}
	l := newLogger(f, opt)
	l.closer = f
	return l, nil
}

// NewWriter logs to w. If w is an io.Closer, Close closes it after draining.
func NewWriter(w io.Writer, opt Options) *Logger {
	l := newLogger(w, opt)
	if c, ok := w.(io.Closer); ok {
		l.closer = c
	}
	return l
}

func newLogger(w io.Writer, opt Options) *Logger {
	if opt.QueueSize <= 0 {
		opt.QueueSize = defaultQueue
	}
	if n := len(opt.Canaries); n > 0 {
		cp := make([]string, n)
		copy(cp, opt.Canaries)
		opt.Canaries = cp
	}
	l := &Logger{opt: opt, out: w, queue: make(chan *item, opt.QueueSize), done: make(chan struct{})}
	go l.run()
	return l
}

// Observe queues the record and waits for the writer to report the result. It returns nil only
// after the record was written. A full queue, a closed logger, a failed writer or an expired
// context is an error. The wait is bounded by ctx, so a stuck disk delays a decision by at most
// the caller's timeout and then fails closed.
func (l *Logger) Observe(ctx context.Context, e policy.Event) error {
	return l.enqueue(ctx, l.record(e))
}

// RecordControl writes a halt or resume line. It is not a tool-call decision.
// kind must be "halt" or "resume".
func (l *Logger) RecordControl(ctx context.Context, kind, reason string) error {
	decision, rule := "HALT", "halt"
	if kind == "resume" {
		decision, rule = "RESUME", "resume"
	} else if kind != "halt" {
		return errors.New("audit: control event must be halt or resume")
	}
	sum := sha256.Sum256(nil)
	rec := Record{
		Time:       time.Now().UTC(),
		Event:      kind,
		Tool:       "halt-control",
		ToolUseID:  "-",
		Decision:   decision,
		Rule:       rule,
		Reason:     truncate(redactWithCanaries(reason, l.opt.Canaries), reasonMax),
		ArgsSHA256: hex.EncodeToString(sum[:]),
	}
	return l.enqueue(ctx, rec)
}

func (l *Logger) enqueue(ctx context.Context, rec Record) error {
	if l.failed.Load() {
		return errFailed
	}
	it := &item{rec: rec, ack: make(chan error, 1)}
	l.mu.RLock()
	if l.closed {
		l.mu.RUnlock()
		return errClosed
	}
	select {
	case l.queue <- it:
		l.mu.RUnlock()
	default:
		l.mu.RUnlock()
		return errFull
	}
	select {
	case err := <-it.ack:
		return err
	case <-ctx.Done():
	}
	if it.state.CompareAndSwap(itemQueued, itemCancelled) {
		return ctx.Err() // not written, and never will be
	}
	// The writer already claimed it: its outcome decides, so wait briefly for it.
	grace := time.NewTimer(claimGrace)
	defer grace.Stop()
	select {
	case err := <-it.ack:
		return err
	case <-grace.C:
		return ctx.Err()
	}
}

func (l *Logger) record(e policy.Event) Record {
	sum := sha256.Sum256(e.Call.Input)
	r := Record{
		Time:       e.End.UTC(),
		Tool:       RedactID(e.Call.Name),
		ToolUseID:  RedactID(e.Call.ID),
		Decision:   string(e.Decision.Verdict),
		Rule:       RedactID(e.Decision.Rule),
		Reason:     truncate(redactWithCanaries(e.Decision.Reason, l.opt.Canaries), reasonMax),
		ArgsSHA256: hex.EncodeToString(sum[:]),
		LatencyMS:  float64(e.End.Sub(e.Start)) / float64(time.Millisecond),
		Stream:     e.Stream,
		Profile:    e.Decision.Profile,
		Event:      e.Kind,
	}
	if e.Agent != "" {
		r.Agent = RedactID(e.Agent)
	}
	if !l.opt.NoPreview {
		r.ArgsPreview = preview(e.Call.Input, previewMax, l.opt.Canaries)
	}
	return r
}

func (l *Logger) run() {
	defer close(l.done)
	enc := json.NewEncoder(l.out)
	for it := range l.queue {
		if !it.state.CompareAndSwap(itemQueued, itemClaimed) {
			continue // cancelled by a caller that gave up; nothing to write or answer
		}
		if l.failed.Load() {
			it.ack <- errFailed // keep draining so the queue cannot fill behind a broken sink
			continue
		}
		if err := enc.Encode(it.rec); err != nil {
			l.failed.Store(true)
			it.ack <- fmt.Errorf("audit: write failed: %w", err)
			continue
		}
		it.ack <- nil
	}
}

// Close stops accepting records, writes what is queued, and closes the destination (once). If the
// writer is still blocked when ctx expires, the destination is closed to try to interrupt it and
// the context error is returned. Go cannot interrupt a Write that is stuck in the kernel or in a
// custom io.Writer: the writer goroutine then ends only when that Write returns.
func (l *Logger) Close(ctx context.Context) error {
	l.mu.Lock()
	if !l.closed {
		l.closed = true
		close(l.queue)
	}
	l.mu.Unlock()
	select {
	case <-l.done:
	case <-ctx.Done():
		l.closeDestination()
		return ctx.Err()
	}
	err := l.closeDestination()
	if err == nil && l.failed.Load() {
		err = errFailed
	}
	return err
}

func (l *Logger) closeDestination() error {
	l.closeOnce.Do(func() {
		if l.closer != nil {
			l.closeErr = l.closer.Close()
		}
	})
	return l.closeErr
}
