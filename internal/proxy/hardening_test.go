package proxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedBuf is a concurrency-safe log sink.
type lockedBuf struct {
	mu sync.Mutex
	sb strings.Builder
}

func (b *lockedBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.Write(p)
}

func (b *lockedBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sb.String()
}

func newLogger(b *lockedBuf) *slog.Logger { return slog.New(slog.NewTextHandler(b, nil)) }

// trickle writes chunk on a ticker until the request context ends, then signals exited.
func trickle(w http.ResponseWriter, r *http.Request, chunk string, exited chan<- struct{}) {
	defer close(exited)
	f := w.(http.Flusher)
	tk := time.NewTicker(10 * time.Millisecond)
	defer tk.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tk.C:
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
			f.Flush()
		}
	}
}

func TestAbsoluteResponseDeadline(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		ctype  string
		prefix string // written before trickling begins
		chunk  string
		check  func(t *testing.T, r rawResp)
	}{
		{
			name: "stream drops held tool call", path: "/v1/messages", ctype: "text/event-stream",
			prefix: msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SENTINEL"}`),
			chunk:  ev("ping", ""),
			check: func(t *testing.T, r rawResp) {
				if !strings.Contains(r.body, "event: error") || strings.Contains(r.body, "message_stop") {
					t.Errorf("expected error event and no message_stop:\n%s", r.body)
				}
				if strings.Contains(r.body, "SENTINEL") || strings.Contains(r.body, "tool_use") {
					t.Errorf("held tool call leaked:\n%s", r.body)
				}
			},
		},
		{
			name: "json", path: "/v1/messages", ctype: "application/json", prefix: `{"content":[`, chunk: " ",
			check: func(t *testing.T, r rawResp) {
				if r.status != 502 {
					t.Errorf("status %d", r.status)
				}
			},
		},
		{
			name: "pass-through", path: "/v1/messages/count_tokens", ctype: "application/json", prefix: `{"input_tokens":`, chunk: " ",
			check: func(t *testing.T, r rawResp) {
				if r.status != 502 {
					t.Errorf("status %d", r.status)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exited := make(chan struct{})
			up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.ctype)
				io.WriteString(w, tc.prefix)
				w.(http.Flusher).Flush()
				trickle(w, r, tc.chunk, exited)
			})
			// StreamIdle stays at its 60s default: only the absolute deadline can end this.
			addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.MaxResponseDuration = 300 * time.Millisecond })
			r := doRaw(t, addr, "POST", tc.path, nil, strings.Replace(reqBody, "%t", "true", 1))
			tc.check(t, r)
			recv(t, exited) // the upstream request was cancelled
		})
	}
}

// parkedUpstream answers only after gate is closed; started is signalled when a request arrives.
func parkedUpstream(t *testing.T, gate <-chan struct{}) (string, <-chan struct{}) {
	started := make(chan struct{}, 16)
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		jsonHandler(msgJSON("end_turn", txt))(w, r)
	})
	return up, started
}

func TestInflightRequestCap(t *testing.T) {
	gate := make(chan struct{})
	up, started := parkedUpstream(t, gate)
	addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.MaxInflightRequests = 1 })
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	})

	first := dial(t, addr)
	sendRequest(t, first, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
	recv(t, started)

	if r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 503 {
		t.Errorf("second request: status %d, want 503", r.status)
	}
	if r := doRaw(t, addr, "GET", "/nope", nil, ""); r.status != 404 {
		t.Errorf("404 route while full: status %d", r.status)
	}

	close(gate)
	resp, err := http.ReadResponse(bufio.NewReader(first), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("first request: status %d", resp.StatusCode)
	}
	if r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 200 {
		t.Errorf("after release: status %d", r.status)
	}
}

func TestInflightSlotsAreReleased(t *testing.T) {
	up := startUpstream(t, jsonHandler(msgJSON("end_turn", txt)))
	addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.MaxInflightRequests = 2; c.MaxBody = 2000 })
	good := strings.Replace(reqBody, "%t", "false", 1)
	for i := 0; i < 8; i++ {
		for _, tc := range []struct {
			body string
			want int
		}{{good, 200}, {`{nope`, 400}, {`{"x":"` + strings.Repeat("a", 3000) + `"}`, 413}} {
			if r := doRaw(t, addr, "POST", "/v1/messages", nil, tc.body); r.status != tc.want {
				t.Fatalf("iteration %d: status %d, want %d", i, r.status, tc.want)
			}
		}
	}
	// A client that disconnects mid-request must also give its slot back.
	gate := make(chan struct{})
	up2, started := parkedUpstream(t, gate)
	addr2 := startProxy(t, up2, decFunc(byName), func(c *Config) { c.MaxInflightRequests = 1 })
	t.Cleanup(func() {
		select {
		case <-gate:
		default:
			close(gate)
		}
	})
	c := dial(t, addr2)
	sendRequest(t, c, "POST", "/v1/messages", nil, good)
	recv(t, started)
	c.Close()
	close(gate)
	deadline := time.Now().Add(testTimeout)
	for {
		if r := doRaw(t, addr2, "POST", "/v1/messages", nil, good); r.status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("slot was not released after client disconnect")
		}
	}
}

// expectResponseThenEOF reads one response and then requires the server to end the connection.
func expectResponseThenEOF(t *testing.T, conn net.Conn, wantStatus int) {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("status %d, want %d", resp.StatusCode, wantStatus)
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err != io.EOF {
		t.Fatalf("connection not closed after response: %v", err)
	}
}

// partialPost sends headers declaring 100 body bytes but only 5, and never finishes.
func partialPost(t *testing.T, conn net.Conn, path string) {
	t.Helper()
	if _, err := io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n12345"); err != nil {
		t.Fatal(err)
	}
}

func TestSlowBodyCannotPinConnection(t *testing.T) {
	t.Run("body timeout", func(t *testing.T) {
		called := make(chan struct{}, 1)
		up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) { called <- struct{}{} })
		addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.BodyTimeout = 200 * time.Millisecond })
		conn := dial(t, addr)
		partialPost(t, conn, "/v1/messages")
		expectResponseThenEOF(t, conn, 400)
		select {
		case <-called:
			t.Error("upstream was called")
		default:
		}
	})
	t.Run("404 route", func(t *testing.T) {
		addr := startProxy(t, startUpstream(t, func(http.ResponseWriter, *http.Request) {}), decFunc(byName), func(c *Config) { c.BodyTimeout = 200 * time.Millisecond })
		conn := dial(t, addr)
		partialPost(t, conn, "/nope")
		expectResponseThenEOF(t, conn, 404)
	})
	t.Run("503 route", func(t *testing.T) {
		gate := make(chan struct{})
		up, started := parkedUpstream(t, gate)
		addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.MaxInflightRequests = 1; c.BodyTimeout = 200 * time.Millisecond })
		t.Cleanup(func() {
			select {
			case <-gate:
			default:
				close(gate)
			}
		})
		first := dial(t, addr)
		sendRequest(t, first, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
		recv(t, started)
		conn := dial(t, addr)
		partialPost(t, conn, "/v1/messages")
		expectResponseThenEOF(t, conn, 503)
	})
}

// A client that never reads a streamed response must not pin the handler. MaxBody and
// MaxResponseDuration are far above what the test sends, so only the write deadline can end it.
func TestStreamWriteDeadline(t *testing.T) {
	big := strings.Repeat("a", 64<<10)
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, msgStart+ev("content_block_start", `,"index":0,"content_block":{"type":"text","text":""}`))
		for r.Context().Err() == nil {
			if _, err := io.WriteString(w, ev("content_block_delta", `,"index":0,"delta":{"type":"text_delta","text":"`+big+`"}`)); err != nil {
				return
			}
			w.(http.Flusher).Flush()
		}
	})
	u, _ := url.Parse(up)
	logs := &lockedBuf{}
	p, err := New(Config{Upstream: u, Decider: decFunc(byName), Logger: newLogger(logs),
		WriteTimeout: 200 * time.Millisecond, MaxBody: 1 << 40, MaxResponseDuration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		p.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	conn := dial(t, srv.Listener.Addr().String())
	sendRequest(t, conn, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "true", 1))
	recv(t, done) // never read from conn
	if !strings.Contains(logs.String(), "client write failed") {
		t.Errorf("handler ended for another reason; log:\n%s", logs.String())
	}
}
