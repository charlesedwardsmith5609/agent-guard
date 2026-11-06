package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"agent-guard/internal/policy"
)

func msgJSON(stop string, blocks ...string) string {
	return `{"id":"m1","type":"message","role":"assistant","model":"x","stop_reason":"` + stop +
		`","content":[` + strings.Join(blocks, ",") + `],"usage":{"input_tokens":1,"output_tokens":1}}`
}

func tu(name, input string) string {
	return `{"type":"tool_use","id":"tu1","name":"` + name + `","input":` + input + `}`
}

const txt = `{"type":"text","text":"hi"}`

func TestNonStream(t *testing.T) {
	cases := []struct {
		name       string
		upstream   string
		mod        func(*Config)
		wantStatus int
		wantTypes  []string // content block types, in order
		wantStop   string
		wantText   string // substring expected in the output
		notText    string // substring that must be absent
	}{
		{name: "no tools", upstream: msgJSON("end_turn", txt), wantStatus: 200, wantTypes: []string{"text"}, wantStop: "end_turn"},
		{name: "allow", upstream: msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`)), wantStatus: 200, wantTypes: []string{"tool_use"}, wantStop: "tool_use", wantText: "KEEP"},
		{name: "block rewrites stop", upstream: msgJSON("tool_use", tu("bad_tool", `{"a":"SECRET"}`)), wantStatus: 200, wantTypes: []string{"text"}, wantStop: "end_turn", wantText: "blocked by policy (rule: r-bad)", notText: "SECRET"},
		{name: "ask", upstream: msgJSON("tool_use", tu("ask_tool", `{"a":"SECRET"}`)), wantStatus: 200, wantTypes: []string{"text"}, wantStop: "end_turn", wantText: "requires approval", notText: "SECRET"},
		{name: "mixed keeps stop", upstream: msgJSON("tool_use", txt, tu("ok_tool", `{}`), tu("bad_tool", `{"a":"SECRET"}`)), wantStatus: 200, wantTypes: []string{"text", "tool_use", "text"}, wantStop: "tool_use", notText: "SECRET"},
		{name: "decider error", upstream: msgJSON("tool_use", tu("err_tool", `{"a":"SECRET"}`)), wantStatus: 200, wantTypes: []string{"text"}, wantStop: "end_turn", wantText: "blocked by policy", notText: "SECRET"},
		{name: "too many calls", upstream: msgJSON("tool_use", tu("ok_tool", `{}`), tu("ok_tool", `{"a":"SECRET"}`)), mod: func(c *Config) { c.MaxToolCalls = 1 }, wantStatus: 200, wantTypes: []string{"tool_use", "text"}, wantStop: "tool_use", wantText: "fail-closed:too-many-calls", notText: "SECRET"},
		{name: "malformed JSON", upstream: `{"content":[`, wantStatus: 502},
		{name: "missing content", upstream: `{"type":"message"}`, wantStatus: 502},
		{name: "bad block", upstream: `{"content":["x"]}`, wantStatus: 502},
		{name: "oversized", upstream: msgJSON("end_turn", txt, txt, txt, txt, txt, txt, txt, txt, txt, txt), mod: func(c *Config) { c.MaxBody = 300 }, wantStatus: 502},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := startUpstream(t, jsonHandler(tc.upstream))
			addr := startProxy(t, up, decFunc(byName), tc.mod)
			r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
			if r.status != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", r.status, tc.wantStatus, r.body)
			}
			if tc.wantStatus != 200 {
				if strings.Contains(r.body, "content") {
					t.Fatalf("original bytes leaked: %s", r.body)
				}
				return
			}
			var out struct {
				StopReason string `json:"stop_reason"`
				Content    []struct {
					Type string `json:"type"`
				} `json:"content"`
			}
			if err := json.Unmarshal([]byte(r.body), &out); err != nil {
				t.Fatal(err)
			}
			var types []string
			for _, c := range out.Content {
				types = append(types, c.Type)
			}
			if strings.Join(types, ",") != strings.Join(tc.wantTypes, ",") {
				t.Errorf("types = %v, want %v", types, tc.wantTypes)
			}
			if out.StopReason != tc.wantStop {
				t.Errorf("stop_reason = %q, want %q", out.StopReason, tc.wantStop)
			}
			if tc.wantText != "" && !strings.Contains(r.body, tc.wantText) {
				t.Errorf("body missing %q: %s", tc.wantText, r.body)
			}
			if tc.notText != "" && strings.Contains(r.body, tc.notText) {
				t.Errorf("body contains %q: %s", tc.notText, r.body)
			}
			if r.header.Get("Etag") != "" {
				t.Errorf("Etag not dropped")
			}
		})
	}
}

func TestRequestHandling(t *testing.T) {
	type seen struct {
		auth, enc, path, query, body string
	}
	ch := make(chan seen, 4)
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- seen{r.Header.Get("X-Api-Key"), r.Header.Get("Accept-Encoding"), r.URL.Path, r.URL.RawQuery, string(b)}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, msgJSON("end_turn", txt))
	})
	rec := &recorder{next: byName}
	addr := startProxy(t, up, rec, func(c *Config) { c.MaxBody = 2000 })

	t.Run("forwards headers and path", func(t *testing.T) {
		r := doRaw(t, addr, "POST", "/v1/messages?beta=true", map[string]string{"X-Api-Key": "k-123", "Accept-Encoding": "gzip"}, strings.Replace(reqBody, "%t", "false", 1))
		if r.status != 200 {
			t.Fatalf("status %d: %s", r.status, r.body)
		}
		s := recv(t, ch)
		if s.auth != "k-123" || s.enc != "identity" || s.path != "/v1/messages" || s.query != "beta=true" {
			t.Errorf("upstream saw %+v", s)
		}
	})

	t.Run("count_tokens is forwarded", func(t *testing.T) {
		r := doRaw(t, addr, "POST", "/v1/messages/count_tokens", nil, `{"x":1}`)
		if r.status != 200 {
			t.Fatalf("status %d", r.status)
		}
		if s := recv(t, ch); s.path != "/v1/messages/count_tokens" {
			t.Errorf("path %q", s.path)
		}
	})

	t.Run("bad request JSON", func(t *testing.T) {
		if r := doRaw(t, addr, "POST", "/v1/messages", nil, `{nope`); r.status != 400 {
			t.Errorf("status %d", r.status)
		}
	})
	t.Run("oversized request", func(t *testing.T) {
		if r := doRaw(t, addr, "POST", "/v1/messages", nil, `{"x":"`+strings.Repeat("a", 3000)+`"}`); r.status != 413 {
			t.Errorf("status %d", r.status)
		}
	})
	for _, tc := range []struct{ method, path string }{
		{"GET", "/v1/messages"}, {"POST", "/v1/other"}, {"POST", "/v1/models"}, {"POST", "/"},
	} {
		t.Run("404 "+tc.method+" "+tc.path, func(t *testing.T) {
			if r := doRaw(t, addr, tc.method, tc.path, nil, `{}`); r.status != 404 {
				t.Errorf("status %d", r.status)
			}
		})
	}
}

func TestUserContext(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
		err  bool
	}{
		{"string content", `{"messages":[{"role":"user","content":"a"},{"role":"assistant","content":"no"},{"role":"user","content":"b"}]}`, []string{"a", "b"}, false},
		{"blocks exclude tool_result", `{"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"tool_result","tool_use_id":"x","content":"evil.example"}]}]}`, []string{"a"}, false},
		{"bad content", `{"messages":[{"role":"user","content":5}]}`, nil, true},
		{"bad json", `{`, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := userContext([]byte(tc.body))
			if (err != nil) != tc.err {
				t.Fatalf("err = %v", err)
			}
			if strings.Join(pc.UserText, "|") != strings.Join(tc.want, "|") {
				t.Errorf("UserText = %v, want %v", pc.UserText, tc.want)
			}
		})
	}
}

func TestDeciderGetsUserText(t *testing.T) {
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{}`))))
	rec := &recorder{next: byName}
	addr := startProxy(t, up, rec, nil)
	body := `{"messages":[{"role":"user","content":"visit example.com"}]}`
	if r := doRaw(t, addr, "POST", "/v1/messages", nil, body); r.status != 200 {
		t.Fatalf("status %d", r.status)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.ctxs) != 1 || len(rec.ctxs[0].UserText) != 1 || rec.ctxs[0].UserText[0] != "visit example.com" {
		t.Errorf("decider context = %+v", rec.ctxs)
	}
}

func TestUpstreamFailures(t *testing.T) {
	t.Run("upstream down", func(t *testing.T) {
		addr := startProxy(t, startClosedURL(t), decFunc(byName), nil)
		if r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 502 {
			t.Errorf("status %d", r.status)
		}
	})
	t.Run("non-2xx passes through", func(t *testing.T) {
		up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(429)
			io.WriteString(w, `{"type":"error","error":{"type":"rate_limit_error"}}`)
		})
		addr := startProxy(t, up, decFunc(byName), nil)
		r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
		if r.status != 429 || !strings.Contains(r.body, "rate_limit_error") {
			t.Errorf("got %d %s", r.status, r.body)
		}
	})
	t.Run("upstream header timeout", func(t *testing.T) {
		release := make(chan struct{})
		up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		})
		addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.UpstreamTimeout = 100 * time.Millisecond })
		t.Cleanup(func() { close(release) })
		if r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 502 {
			t.Errorf("status %d", r.status)
		}
	})
}

func TestPassThroughBuffering(t *testing.T) {
	big := strings.Repeat("A", maxPassThroughBody+10)
	cases := []struct {
		name       string
		path       string
		handler    http.HandlerFunc
		wantStatus int
		wantBody   string
		notBody    string
	}{
		{"small count_tokens", "/v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"input_tokens":3}`)
		}, 200, `{"input_tokens":3}`, ""},
		{"oversized count_tokens", "/v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "sentinel=1")
			io.WriteString(w, big)
		}, 502, "rejected", "AAAA"},
		{"oversized error body", "/v1/messages", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "sentinel=1")
			w.WriteHeader(500)
			io.WriteString(w, big)
		}, 502, "rejected", "AAAA"},
		{"truncated body", "/v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "1000")
			w.Header().Set("Set-Cookie", "sentinel=1")
			io.WriteString(w, "PREFIX-SENSITIVE")
		}, 502, "rejected", "PREFIX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := startProxy(t, startUpstream(t, tc.handler), decFunc(byName), nil)
			r := doRaw(t, addr, "POST", tc.path, nil, strings.Replace(reqBody, "%t", "false", 1))
			if r.status != tc.wantStatus || !strings.Contains(r.body, tc.wantBody) {
				t.Fatalf("got %d %.200s", r.status, r.body)
			}
			if tc.notBody != "" && strings.Contains(r.body, tc.notBody) {
				t.Errorf("partial body leaked")
			}
			if tc.wantStatus == 502 && (r.header.Get("Set-Cookie") != "" || r.header.Get("Content-Encoding") != "") {
				t.Errorf("upstream headers leaked onto rejection: %v", r.header)
			}
		})
	}
}

func TestUpstreamURLIsCopied(t *testing.T) {
	up := startUpstream(t, jsonHandler(msgJSON("end_turn", txt)))
	u, err := url.Parse(up)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Upstream: u, Decider: policy.DenyAll{}})
	if err != nil {
		t.Fatal(err)
	}
	u.Host = "127.0.0.1:1" // caller mutates its URL after New
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	if r := doRaw(t, srv.Listener.Addr().String(), "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 200 {
		t.Fatalf("status %d: %s", r.status, r.body)
	}
}

// A client that never reads a response larger than the socket buffers must not pin the handler:
// the write deadline ends it. done is signalled when the handler returns.
func TestJSONWriteDeadline(t *testing.T) {
	huge := msgJSON("end_turn", `{"type":"text","text":"`+strings.Repeat("a", 12<<20)+`"}`)
	up := startUpstream(t, jsonHandler(huge))
	u, err := url.Parse(up)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(Config{Upstream: u, Decider: policy.DenyAll{}, MaxBody: 64 << 20, WriteTimeout: 200 * time.Millisecond})
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
	sendRequest(t, conn, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
	start := time.Now()
	select {
	case <-done:
		t.Logf("handler returned after %v", time.Since(start))
	case <-time.After(30 * time.Second):
		t.Fatal("handler still blocked after 30s")
	}
}

func TestClientDisconnectCancelsUpstream(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // net/http only watches for disconnect after the body is read
		close(started)
		<-r.Context().Done()
		close(cancelled)
	})
	addr := startProxy(t, up, decFunc(byName), nil)
	conn := dial(t, addr)
	sendRequest(t, conn, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
	recv(t, started)
	conn.Close()
	recv(t, cancelled)
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("expected error for empty config")
	}
	if _, err := New(Config{Decider: policy.DenyAll{}}); err == nil {
		t.Error("expected error for missing upstream")
	}
}
