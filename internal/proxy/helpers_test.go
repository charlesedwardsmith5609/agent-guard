package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-guard/internal/policy"
)

const testTimeout = 5 * time.Second

type decFunc func(ctx context.Context, c policy.Context, t policy.ToolCall) (policy.Decision, error)

func (f decFunc) Decide(ctx context.Context, c policy.Context, t policy.ToolCall) (policy.Decision, error) {
	return f(ctx, c, t)
}

// byName decides by tool name: ok_tool allows, bad_tool blocks, ask_tool asks, err_tool errors.
func byName(_ context.Context, _ policy.Context, t policy.ToolCall) (policy.Decision, error) {
	switch t.Name {
	case "ok_tool":
		return policy.Decision{Verdict: policy.Allow, Rule: "r-ok"}, nil
	case "ask_tool":
		return policy.Decision{Verdict: policy.Ask, Rule: "r-ask"}, nil
	case "err_tool":
		return policy.Decision{}, fmt.Errorf("boom")
	}
	return policy.Decision{Verdict: policy.Block, Rule: "r-bad"}, nil
}

// recObs is a concurrency-safe Observer that records events and can be told to fail.
type recObs struct {
	mu     sync.Mutex
	events []policy.Event
	err    error
	ctxErr []error
	got    chan struct{} // one token per observed event (non-blocking send)
}

func (r *recObs) Observe(ctx context.Context, e policy.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	r.ctxErr = append(r.ctxErr, ctx.Err())
	select {
	case r.got <- struct{}{}:
	default:
	}
	return r.err
}

func (r *recObs) snapshot() []policy.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]policy.Event(nil), r.events...)
}

func (r *recObs) setErr(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

// startProxy starts a Proxy on a loopback listener (port 0) and returns its address.
func startProxy(t *testing.T, upstream string, d policy.Decider, mod func(*Config)) string {
	t.Helper()
	addr, _ := startProxyObs(t, upstream, d, mod)
	return addr
}

// startProxyObs is startProxy that also returns the audit observer it installed.
func startProxyObs(t *testing.T, upstream string, d policy.Decider, mod func(*Config)) (string, *recObs) {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	obs := &recObs{got: make(chan struct{}, 256)}
	cfg := Config{Upstream: u, Decider: d, Audit: obs}
	if mod != nil {
		mod(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String(), obs
}

func startUpstream(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, testTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

type rawResp struct {
	status int
	header http.Header
	body   string
}

func sendRequest(t *testing.T, conn net.Conn, method, path string, hdr map[string]string, body string) {
	t.Helper()
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: %d\r\n", method, path, len(body))
	for k, v := range hdr {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	sb.WriteString("\r\n" + body)
	if _, err := io.WriteString(conn, sb.String()); err != nil {
		t.Fatal(err)
	}
}

// doRaw sends one request over a raw connection with a deadline and reads the whole response.
func doRaw(t *testing.T, addr, method, path string, hdr map[string]string, body string) rawResp {
	t.Helper()
	conn := dial(t, addr)
	sendRequest(t, conn, method, path, hdr, body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return rawResp{resp.StatusCode, resp.Header, string(b)}
}

const reqBody = `{"model":"m","max_tokens":10,"stream":%t,"messages":[{"role":"user","content":"hello"}]}`

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

// ---- SSE builders ----

func ev(typ, fields string) string {
	return "event: " + typ + "\ndata: {\"type\":\"" + typ + "\"" + fields + "}\n\n"
}

const msgStart = `event: message_start
data: {"type":"message_start","message":{"id":"m1","type":"message","role":"assistant","content":[],"model":"x","stop_reason":null,"usage":{"input_tokens":1,"output_tokens":1}}}

`

func msgDelta(stop string) string {
	return ev("message_delta", `,"delta":{"stop_reason":"`+stop+`","stop_sequence":null},"usage":{"output_tokens":5}`)
}

var msgStop = ev("message_stop", "")

func textBlock(idx int, txt string) string {
	return ev("content_block_start", fmt.Sprintf(`,"index":%d,"content_block":{"type":"text","text":""}`, idx)) +
		ev("content_block_delta", fmt.Sprintf(`,"index":%d,"delta":{"type":"text_delta","text":%q}`, idx, txt)) +
		ev("content_block_stop", fmt.Sprintf(`,"index":%d`, idx))
}

func toolStart(idx int, name string) string {
	return ev("content_block_start", fmt.Sprintf(`,"index":%d,"content_block":{"type":"tool_use","id":"tu%d","name":%q,"input":{}}`, idx, idx, name))
}

func toolDelta(idx int, part string) string {
	b, _ := json.Marshal(part)
	return ev("content_block_delta", fmt.Sprintf(`,"index":%d,"delta":{"type":"input_json_delta","partial_json":%s}`, idx, b))
}

func blockStop(idx int) string { return ev("content_block_stop", fmt.Sprintf(`,"index":%d`, idx)) }

func toolBlock(idx int, name string, parts ...string) string {
	s := toolStart(idx, name)
	for _, p := range parts {
		s += toolDelta(idx, p)
	}
	return s + blockStop(idx)
}

// sseHandler serves a fixed SSE body.
func sseHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, body)
	}
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", `"stale"`)
		io.WriteString(w, body)
	}
}

// recorder is a concurrency-safe Decider wrapper that records contexts.
type recorder struct {
	mu   sync.Mutex
	ctxs []policy.Context
	next decFunc
}

func (r *recorder) Decide(ctx context.Context, c policy.Context, t policy.ToolCall) (policy.Decision, error) {
	r.mu.Lock()
	r.ctxs = append(r.ctxs, c)
	r.mu.Unlock()
	return r.next(ctx, c, t)
}

// startClosedURL returns the URL of a loopback address nothing is listening on.
func startClosedURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return "http://" + addr
}
