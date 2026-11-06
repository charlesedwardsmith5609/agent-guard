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
}

// RedactID makes an untrusted identifier (tool name, tool_use id) safe to record or export:
// restricted to a small alphabet, then stripped of credential-shaped text.
func RedactID(s string) string { return redactString(policy.SafeID(s)) }

// Options configures a Logger.
type Options struct {
	QueueSize int  // records buffered before Observe starts failing (default 4096)
	NoPreview bool // record only the argument hash
}

var (
	errClosed = errors.New("audit: logger is closed")
	errFailed = errors.New("audit: writer has failed")
	errFull   = errors.New("audit: queue is full")
)

// Logger implements policy.Observer.
//
// Ownership: one writer goroutine owns the destination and the encoder. Other goroutines only
// send Record values on queue with a non-blocking send. The RWMutex guards just the closed flag
// and the close of queue: Observe holds the read lock across its send and Close takes the write
// lock before closing the channel, so no send can race the close.
type Logger struct {
	opt    Options
	out    io.Writer
	closer io.Closer

	mu     sync.RWMutex
	closed bool
	queue  chan Record

	failed atomic.Bool
	done   chan struct{}
}

// Open appends to path. It rejects symlinks, non-regular files and files readable or writable by
// group or others (it does not silently change permissions on a file it did not create).
func Open(path string, opt Options) (*Logger, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("audit: %s is not a regular file", path)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("audit: %s has mode %o; want 0600", path, fi.Mode().Perm())
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("audit: %s is not a private regular file", path)
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
	l := &Logger{opt: opt, out: w, queue: make(chan Record, opt.QueueSize), done: make(chan struct{})}
	go l.run()
	return l
}

// Observe queues a record without blocking. An error means the event was not recorded.
func (l *Logger) Observe(_ context.Context, e policy.Event) error {
	if l.failed.Load() {
		return errFailed
	}
	rec := l.record(e)
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return errClosed
	}
	select {
	case l.queue <- rec:
		return nil
	default:
		return errFull
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
		Reason:     truncate(redactString(e.Decision.Reason), reasonMax),
		ArgsSHA256: hex.EncodeToString(sum[:]),
		LatencyMS:  float64(e.End.Sub(e.Start)) / float64(time.Millisecond),
		Stream:     e.Stream,
	}
	if !l.opt.NoPreview {
		r.ArgsPreview = preview(e.Call.Input, previewMax)
	}
	return r
}

func (l *Logger) run() {
	defer close(l.done)
	enc := json.NewEncoder(l.out)
	for rec := range l.queue {
		if l.failed.Load() {
			continue // keep draining so the queue cannot fill behind a broken sink
		}
		if err := enc.Encode(rec); err != nil {
			l.failed.Store(true)
		}
	}
}

// Close stops accepting records, writes what is queued, and closes the destination. If the
// writer is blocked past ctx it returns ctx.Err() and abandons the writer goroutine.
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
		return ctx.Err()
	}
	var err error
	if l.closer != nil {
		err = l.closer.Close()
	}
	if err == nil && l.failed.Load() {
		err = errFailed
	}
	return err
}
