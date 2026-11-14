package audit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"agent-guard/internal/policy"
)

const testTimeout = 5 * time.Second

func init() { claimGrace = 20 * time.Millisecond } // keep timeout tests quick

// Fake credentials are assembled at run time so no secret-shaped literal exists in the source.
var fixtures = map[string]string{
	"SK":     "sk" + "-" + "abcdefghijklmnopqrstuvwxyz",
	"GHP":    "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789",
	"AWSID":  "AK" + "IA" + "IOSFODNN7EXAMPLE",
	"JWT":    "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dBjftJeZ4CVPmB92K27uhbUJU1p1r",
	"BEARER": "abcdefghijkl" + "12345",
	"PEM":    "-----BEGIN RSA PRIVATE" + " KEY-----",
	"BASICH": "Ba" + "sic dXNlcjpwYXNzd29yZA==",
	"CREDS":  "ali" + "ce:hun" + "ter2",
}

// fx replaces @NAME@ placeholders with the fixtures above.
func fx(s string) string {
	for k, v := range fixtures {
		s = strings.ReplaceAll(s, "@"+k+"@", v)
	}
	return s
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func ev(tool, id, input string, v policy.Verdict, rule, reason string) policy.Event {
	start := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	return policy.Event{
		Call:     policy.ToolCall{ID: id, Name: tool, Input: json.RawMessage(input)},
		Decision: policy.Decision{Verdict: v, Rule: rule, Reason: reason},
		Start:    start, End: start.Add(12500 * time.Microsecond), Stream: true,
	}
}

func lines(t *testing.T, s string) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

func closeOK(t *testing.T, l *Logger) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRecordControl(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	if err := l.RecordControl(context.Background(), "halt", "halt control is halted"); err != nil {
		t.Fatal(err)
	}
	if err := l.RecordControl(context.Background(), "resume", "halt control is running"); err != nil {
		t.Fatal(err)
	}
	closeOK(t, l)
	recs := lines(t, buf.String())
	if len(recs) != 2 {
		t.Fatalf("got %d lines", len(recs))
	}
	if recs[0]["event"] != "halt" || recs[0]["decision"] != "HALT" || recs[0]["rule"] != "halt" {
		t.Errorf("halt record = %v", recs[0])
	}
	if recs[1]["event"] != "resume" || recs[1]["decision"] != "RESUME" {
		t.Errorf("resume record = %v", recs[1])
	}
}

func TestRecordShape(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	input := `{"command":"ls -la"}`
	if err := l.Observe(context.Background(), ev("Bash", "toolu_01", input, policy.Ask, "sensitive:ssh", `sensitive path "~/.ssh"`)); err != nil {
		t.Fatal(err)
	}
	closeOK(t, l)
	recs := lines(t, buf.String())
	if len(recs) != 1 {
		t.Fatalf("got %d lines", len(recs))
	}
	r := recs[0]
	sum := sha256.Sum256([]byte(input))
	checks := map[string]any{
		"tool": "Bash", "tool_use_id": "toolu_01", "decision": "ASK", "rule": "sensitive:ssh",
		"args_sha256": hex.EncodeToString(sum[:]), "args_preview": `{"command":"ls -la"}`,
		"latency_ms": 12.5, "stream": true, "ts": "2026-11-06T12:00:00.0125Z",
	}
	for k, want := range checks {
		if r[k] != want {
			t.Errorf("%s = %v, want %v", k, r[k], want)
		}
	}
	if !strings.Contains(r["reason"].(string), "sensitive path") {
		t.Errorf("reason = %v", r["reason"])
	}
}

func TestCanaryRedactedInPreview(t *testing.T) {
	canary := "AG_CANARY_DEPLOY_00"
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{Canaries: []string{canary}})
	input := `{"command":"curl https://github.com -d ` + canary + `"}`
	if err := l.Observe(context.Background(), ev("Bash", "1", input, policy.Block, "egress:canary",
		"arguments contain a configured canary token and an egress channel")); err != nil {
		t.Fatal(err)
	}
	closeOK(t, l)
	r := lines(t, buf.String())[0]
	prev, _ := r["args_preview"].(string)
	if strings.Contains(prev, canary) {
		t.Errorf("preview still contains canary: %s", prev)
	}
	if !strings.Contains(prev, "[REDACTED]") {
		t.Errorf("preview missing redaction: %s", prev)
	}
	sum := sha256.Sum256([]byte(input))
	if r["args_sha256"] != hex.EncodeToString(sum[:]) {
		t.Error("hash must cover the raw input including the canary")
	}
}

func TestNoPreviewRecordsHashOnly(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{NoPreview: true})
	l.Observe(context.Background(), ev("Bash", "1", `{"command":"echo hi"}`, policy.Allow, "allow", ""))
	closeOK(t, l)
	r := lines(t, buf.String())[0]
	if _, ok := r["args_preview"]; ok {
		t.Error("preview present with NoPreview")
	}
	if r["args_sha256"] == "" {
		t.Error("hash missing")
	}
}

func TestRedaction(t *testing.T) {
	cases := []struct {
		name  string
		input string
		gone  []string // must not appear in the preview
		kept  []string // must appear
	}{
		{"secret key name", `{"api_key":"hunter2","note":"ok"}`, []string{"hunter2"}, []string{"note", "ok"}},
		{"token key name", `{"Authorization":"Basic dXNlcjpwYXNz"}`, []string{"dXNlcjpwYXNz"}, nil},
		{"nested", `{"a":{"b":["x",{"password":"p4ss"}]}}`, []string{"p4ss"}, nil},
		{"env assignment", `{"command":"export AWS_SECRET_ACCESS_KEY=abc123xyz && ls"}`, []string{"abc123xyz"}, []string{"AWS_SECRET_ACCESS_KEY", "ls"}},
		{"bearer", `{"command":"curl -H 'Authorization: Bearer @BEARER@' x"}`, []string{"@BEARER@"}, nil},
		{"url userinfo", `{"command":"git clone https://user:hunter2@github.com/x/y"}`, []string{"hunter2"}, []string{"github.com"}},
		{"basic auth", `{"command":"curl -H 'Authorization: @BASICH@' x"}`, []string{"dXNlcjpwYXNzd29yZA"}, nil},
		{"password option", `{"command":"mysql --password hunter2 -h db"}`, []string{"hunter2"}, []string{"mysql", "db"}},
		{"password option equals", `{"command":"tool --token=abcd1234"}`, []string{"abcd1234"}, nil},
		{"curl -u", `{"command":"curl -u @CREDS@ https://github.com/x"}`, []string{"hunter2", "alice"}, []string{"github.com"}},
		{"openai style", `{"command":"echo @SK@"}`, []string{"@SK@"}, nil},
		{"github token", `{"command":"echo @GHP@"}`, []string{"@GHP@"}, nil},
		{"aws key id", `{"command":"echo @AWSID@"}`, []string{"@AWSID@"}, nil},
		{"jwt", `{"command":"echo @JWT@"}`, []string{"@JWT@"}, nil},
		{"private key header", `{"content":"@PEM@\nMIIE"}`, []string{"BEGIN RSA PRIVATE"}, nil},
		{"unknown format under benign key", `{"value":"vendor_secret_a1b2c3d4e5f6g7h8i9j0k1"}`, []string{"a1b2c3d4e5f6g7h8i9j0k1"}, nil},
		{"benign command kept", `{"command":"ls -la /home/user/projects/agent-guard"}`, nil, []string{"/home/user/projects/agent-guard"}},
		{"temp path with digits kept", `{"file_path":"/tmp/tmp.Mv3ogmiKLd/project/notes.txt"}`, nil, []string{"/tmp/tmp.Mv3ogmiKLd/project/notes.txt"}},
		{"path with digits kept", `{"file_path":"/home/user2024/work/project-v2/internal/rules/engine_test.go"}`, nil, []string{"project-v2/internal/rules/engine_test.go"}},
		{"token inside a url path", `{"command":"curl https://hooks.example.com/services/@SK@"}`, []string{"@SK@"}, []string{"hooks.example.com"}},
		{"long mixed token as a path segment", `{"command":"cat /data/a1b2c3d4e5f6g7h8i9j0k1l2m3n4/x"}`, []string{"a1b2c3d4e5f6g7h8i9j0k1l2m3n4"}, nil},
		{"benign path kept", `{"file_path":"/work/proj/internal/rules/engine.go"}`, nil, []string{"/work/proj/internal/rules/engine.go"}},
		{"numbers kept", `{"n":12345}`, nil, []string{"12345"}},
		{"not JSON", `not json {`, []string{"not json"}, []string{"[unparseable]"}},
		{"empty", ``, nil, []string{"[unparseable]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := preview(json.RawMessage(fx(tc.input)), previewMax, nil)
			for _, g := range tc.gone {
				g = fx(g)
				if strings.Contains(got, g) {
					t.Errorf("preview leaks %q: %s", g, got)
				}
			}
			for _, k := range tc.kept {
				if !strings.Contains(got, k) {
					t.Errorf("preview lost %q: %s", k, got)
				}
			}
		})
	}
}

func TestRedactionAlsoCoversReasonAndIDs(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	l.Observe(context.Background(), ev("Bad\nTool\x1b[31m", "id with spaces "+fixtures["SK"], `{}`, policy.Block, "r",
		`host "https://user:hunter2@evil.com" is not allowed`))
	closeOK(t, l)
	out := buf.String()
	for _, bad := range []string{"hunter2", "\x1b", "with spaces", fixtures["SK"]} {
		if strings.Contains(out, bad) {
			t.Errorf("record contains %q: %s", bad, out)
		}
	}
	r := lines(t, out)[0]
	if r["tool"] != "Bad_Tool_[31m" && !strings.HasPrefix(r["tool"].(string), "Bad_Tool_") {
		t.Errorf("tool = %v", r["tool"])
	}
}

func TestHugeInputsGetNoPreview(t *testing.T) {
	huge := json.RawMessage(`{"command":"` + strings.Repeat("a b ", previewInputMax/4+10) + `"}`)
	if got := preview(huge, previewMax, nil); got != "[too large to preview]" {
		t.Errorf("got %q", got[:min(len(got), 40)])
	}
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	l.Observe(context.Background(), policy.Event{Call: policy.ToolCall{Name: "T", ID: "1", Input: huge}, Decision: policy.Decision{Verdict: policy.Allow, Rule: "allow"}})
	closeOK(t, l)
	r := lines(t, buf.String())[0]
	if r["args_sha256"] == "" || r["args_preview"] != "[too large to preview]" {
		t.Errorf("record = %v", r)
	}
}

func TestTruncation(t *testing.T) {
	long := `{"command":"` + strings.Repeat("a", 1000) + `"}`
	got := preview(json.RawMessage(long), previewMax, nil)
	if len(got) > previewMax || !strings.HasSuffix(got, "...") {
		t.Errorf("len %d: %.40s...", len(got), got)
	}
	multi := `{"command":"` + strings.Repeat("é", 500) + `"}` // two bytes per rune
	for max := 20; max < 60; max++ {
		if g := truncate(multi, max); !utf8.ValidString(g) || len(g) > max {
			t.Fatalf("max %d: invalid or too long: %q", max, g)
		}
	}
	if g := truncate("short", 100); g != "short" {
		t.Errorf("short string changed: %q", g)
	}
}

func TestOpenFilePermissions(t *testing.T) {
	dir := t.TempDir()
	t.Run("new file is 0600", func(t *testing.T) {
		p := filepath.Join(dir, "new.jsonl")
		l, err := Open(p, Options{})
		if err != nil {
			t.Fatal(err)
		}
		closeOK(t, l)
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %o", fi.Mode().Perm())
		}
	})
	t.Run("existing private file is appended to", func(t *testing.T) {
		p := filepath.Join(dir, "append.jsonl")
		for i := 0; i < 2; i++ {
			l, err := Open(p, Options{})
			if err != nil {
				t.Fatal(err)
			}
			l.Observe(context.Background(), ev("T", "1", `{}`, policy.Allow, "allow", ""))
			closeOK(t, l)
		}
		b, _ := os.ReadFile(p)
		if n := len(lines(t, string(b))); n != 2 {
			t.Errorf("got %d lines, want 2", n)
		}
	})
	t.Run("permissive existing file is rejected", func(t *testing.T) {
		p := filepath.Join(dir, "open.jsonl")
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o644)
		if _, err := Open(p, Options{}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("symlink is rejected", func(t *testing.T) {
		target := filepath.Join(dir, "target.jsonl")
		os.WriteFile(target, nil, 0o600)
		link := filepath.Join(dir, "link.jsonl")
		if err := os.Symlink(target, link); err != nil {
			t.Skip("symlinks unavailable")
		}
		if _, err := Open(link, Options{}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("directory is rejected", func(t *testing.T) {
		if _, err := Open(dir, Options{}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("missing directory is rejected", func(t *testing.T) {
		if _, err := Open(filepath.Join(dir, "no", "such", "dir.jsonl"), Options{}); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestCloseDrainsEverything(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{QueueSize: 1000})
	for i := 0; i < 500; i++ {
		if err := l.Observe(context.Background(), ev("T", "1", `{}`, policy.Allow, "allow", "")); err != nil {
			t.Fatal(err)
		}
	}
	closeOK(t, l)
	if n := len(lines(t, buf.String())); n != 500 {
		t.Errorf("got %d lines, want 500", n)
	}
}

func TestObserveAfterClose(t *testing.T) {
	l := NewWriter(&lockedBuf{}, Options{})
	closeOK(t, l)
	closeOK(t, l) // idempotent
	if err := l.Observe(context.Background(), ev("T", "1", `{}`, policy.Allow, "allow", "")); err == nil {
		t.Error("expected an error after Close")
	}
}

// gatedWriter blocks every Write until gate is closed.
type gatedWriter struct {
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func newGated() *gatedWriter {
	return &gatedWriter{gate: make(chan struct{}), entered: make(chan struct{})}
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	g.once.Do(func() { close(g.entered) })
	<-g.gate
	return len(p), nil
}

func (g *gatedWriter) release() {
	select {
	case <-g.gate:
	default:
		close(g.gate)
	}
}

func awaitEntered(t *testing.T, g *gatedWriter) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(testTimeout):
		t.Fatal("the writer never started writing")
	}
}

// Observe returns nil only after the record was written: while the write is stuck it waits, and
// when its context ends it reports failure instead of pretending success.
func TestObserveWaitsForTheWrite(t *testing.T) {
	g := newGated()
	l := NewWriter(g, Options{})
	t.Cleanup(g.release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := l.Observe(ctx, ev("T", "1", `{}`, policy.Allow, "allow", ""))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Observe returned %v while the write was still blocked; want the context error", err)
	}
	g.release()
	if err := l.Observe(context.Background(), ev("T", "2", `{}`, policy.Allow, "allow", "")); err != nil {
		t.Fatalf("Observe after the writer recovered: %v", err)
	}
	closeOK(t, l)
}

// If the caller gives up while its record is still queued behind a stuck write, the record is
// cancelled: it must never appear in the log afterwards as a decision that was not delivered.
func TestCancelledRecordIsNeverWritten(t *testing.T) {
	g := newGated()
	buf := &lockedBuf{}
	l := NewWriter(struct {
		io.Writer
	}{io.MultiWriter(g, buf)}, Options{})
	t.Cleanup(g.release)
	first := make(chan error, 1)
	go func() { first <- l.Observe(context.Background(), ev("First", "1", `{}`, policy.Allow, "allow", "")) }()
	awaitEntered(t, g) // First is claimed and stuck in Write
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := l.Observe(ctx, ev("Second", "2", `{}`, policy.Allow, "allow", "")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Second = %v, want the context error", err)
	}
	g.release()
	if err := recv(t, first); err != nil {
		t.Fatal(err)
	}
	closeOK(t, l)
	if out := buf.String(); !strings.Contains(out, `"First"`) || strings.Contains(out, `"Second"`) {
		t.Errorf("log must hold First only, got:\n%s", out)
	}
}

func TestFullQueueFailsWithoutBlocking(t *testing.T) {
	g := newGated()
	l := NewWriter(g, Options{QueueSize: 2})
	t.Cleanup(g.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := ev("T", "1", `{}`, policy.Allow, "allow", "")
	results := make(chan error, 8)
	observe := func() { results <- l.Observe(ctx, e) }
	go observe()
	awaitEntered(t, g) // the writer holds one record, blocked in Write
	for i := 0; i < 5; i++ {
		go observe() // two fit in the queue and wait; the rest must fail at once
	}
	for i := 0; i < 3; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, errFull) {
				t.Fatalf("got %v, want the queue-full error", err)
			}
		case <-time.After(testTimeout):
			t.Fatal("Observe blocked on a full queue")
		}
	}
	cancel() // the three waiting callers give up
	for i := 0; i < 3; i++ {
		if err := recv(t, results); !errors.Is(err, context.Canceled) {
			t.Errorf("waiting caller got %v", err)
		}
	}
	g.release()
	closeOK(t, l)
}

func recv[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting")
		panic("unreachable")
	}
}

func TestCloseWithBlockedWriterHonoursContext(t *testing.T) {
	g := newGated()
	l := NewWriter(g, Options{})
	t.Cleanup(g.release)
	obsCtx, stopObs := context.WithCancel(context.Background())
	defer stopObs()
	go l.Observe(obsCtx, ev("T", "1", `{}`, policy.Allow, "allow", ""))
	awaitEntered(t, g)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Close(ctx) }()
	if err := recv(t, done); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}

type countingCloser struct {
	lockedBuf
	mu     sync.Mutex
	closed int
}

func (c *countingCloser) Close() error { c.mu.Lock(); c.closed++; c.mu.Unlock(); return nil }
func (c *countingCloser) count() int   { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }

func TestDestinationClosedExactlyOnce(t *testing.T) {
	c := &countingCloser{}
	l := NewWriter(c, Options{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); closeOK(t, l) }()
	}
	wg.Wait()
	if c.count() != 1 {
		t.Errorf("destination closed %d times", c.count())
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// A write failure must reach the Observe call that queued the record, so the proxy can refuse
// the ALLOW; later calls fail fast.
func TestWriteFailureReachesTheCaller(t *testing.T) {
	l := NewWriter(failWriter{}, Options{})
	e := ev("T", "1", `{}`, policy.Allow, "allow", "")
	err := l.Observe(context.Background(), e)
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("first Observe = %v, want the write error", err)
	}
	if err := l.Observe(context.Background(), e); !errors.Is(err, errFailed) {
		t.Fatalf("later Observe = %v, want errFailed", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	if err := l.Close(ctx); !errors.Is(err, errFailed) {
		t.Errorf("Close = %v, want the writer failure", err)
	}
}

func TestConcurrentObserveLosesNothing(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{QueueSize: 8192})
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				if err := l.Observe(context.Background(), ev("T", "1", `{"n":1}`, policy.Allow, "allow", "")); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	closeOK(t, l)
	if n := len(lines(t, buf.String())); n != 3200 {
		t.Errorf("got %d lines, want 3200", n)
	}
}

// Observe racing Close must either record or return an error, never panic.
func TestObserveRacingClose(t *testing.T) {
	for i := 0; i < 50; i++ {
		l := NewWriter(&lockedBuf{}, Options{QueueSize: 16})
		var wg sync.WaitGroup
		for g := 0; g < 4; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					l.Observe(context.Background(), ev("T", "1", `{}`, policy.Allow, "allow", ""))
				}
			}()
		}
		closeOK(t, l)
		wg.Wait()
	}
}

func TestCredentialShapedToolNamesAreRedacted(t *testing.T) {
	buf := &lockedBuf{}
	l := NewWriter(buf, Options{})
	l.Observe(context.Background(), ev(fixtures["SK"], fixtures["GHP"], `{}`, policy.Block, "r", ""))
	closeOK(t, l)
	if out := buf.String(); strings.Contains(out, "abcdefghijklmnop") {
		t.Errorf("record leaks a credential-shaped name or id: %s", out)
	}
}
