// Package proxy implements the agent-guard reverse proxy for the Anthropic Messages API.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"agent-guard/internal/policy"
)

// Config configures a Proxy. Zero numeric fields take the defaults shown.
type Config struct {
	Upstream *url.URL       // required
	Decider  policy.Decider // required; must be safe for concurrent use
	Logger   *slog.Logger   // optional; nil discards

	MaxBody              int64         // 32 MiB: request and response body cap
	MaxToolCalls         int           // 64: tool calls inspected per response
	MaxHeldBytes         int64         // 1 MiB: bytes held for one streamed tool call
	MaxInflightDecisions int           // 64: concurrent Decider goroutines
	DecideTimeout        time.Duration // 5s
	UpstreamTimeout      time.Duration // 30s: wait for upstream response headers
	StreamIdle           time.Duration // 60s: max silence on an upstream body
	WriteTimeout         time.Duration // 30s: deadline for each write to the client
	BodyTimeout          time.Duration // 30s: deadline for reading the request body
}

func (c *Config) applyDefaults() {
	if c.MaxBody <= 0 {
		c.MaxBody = 32 << 20
	}
	if c.MaxToolCalls <= 0 {
		c.MaxToolCalls = 64
	}
	if c.MaxHeldBytes <= 0 {
		c.MaxHeldBytes = 1 << 20
	}
	if c.MaxInflightDecisions <= 0 {
		c.MaxInflightDecisions = 64
	}
	for _, p := range []struct {
		v *time.Duration
		d time.Duration
	}{
		{&c.DecideTimeout, 5 * time.Second},
		{&c.UpstreamTimeout, 30 * time.Second},
		{&c.StreamIdle, 60 * time.Second},
		{&c.WriteTimeout, 30 * time.Second},
		{&c.BodyTimeout, 30 * time.Second},
	} {
		if *p.v <= 0 {
			*p.v = p.d
		}
	}
}

// Proxy is an http.Handler. All fields are immutable after New.
type Proxy struct {
	cfg    Config
	guard  *guard
	client *http.Client
	log    *slog.Logger
}

// New validates cfg and returns a Proxy.
func New(cfg Config) (*Proxy, error) {
	if cfg.Upstream == nil || cfg.Upstream.Host == "" || (cfg.Upstream.Scheme != "http" && cfg.Upstream.Scheme != "https") {
		return nil, errors.New("proxy: upstream must be an http(s) URL with a host")
	}
	if cfg.Decider == nil {
		return nil, errors.New("proxy: decider is required")
	}
	cfg.applyDefaults()
	u := *cfg.Upstream // private copy: later changes by the caller must not reroute traffic
	cfg.Upstream = &u
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ResponseHeaderTimeout = cfg.UpstreamTimeout
	lg := cfg.Logger
	if lg == nil {
		lg = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Proxy{
		cfg:    cfg,
		guard:  newGuard(cfg.Decider, cfg.DecideTimeout, cfg.MaxInflightDecisions),
		client: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		log:    lg,
	}, nil
}

const (
	pathMessages = "/v1/messages"
	pathCount    = "/v1/messages/count_tokens"
)

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	if r.Method != http.MethodPost || (r.URL.Path != pathMessages && r.URL.Path != pathCount) {
		setDeadline(rc.SetWriteDeadline, p.cfg.WriteTimeout)
		http.NotFound(w, r)
		return
	}
	setDeadline(rc.SetReadDeadline, p.cfg.BodyTimeout)
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, p.cfg.MaxBody))
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			p.fail(w, rc, http.StatusRequestEntityTooLarge, "request body too large")
		} else {
			p.fail(w, rc, http.StatusBadRequest, "could not read request body")
		}
		return
	}
	inspect := r.URL.Path == pathMessages
	var pc policy.Context
	if inspect {
		pc, err = userContext(body)
		if err != nil {
			p.fail(w, rc, http.StatusBadRequest, "invalid request JSON")
			return
		}
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	resp, err := p.forward(ctx, r, body)
	if err != nil {
		p.log.Warn("upstream request failed", "err", err)
		p.fail(w, rc, http.StatusBadGateway, "upstream request failed")
		return
	}
	resp.Body = newIdleBody(resp.Body, p.cfg.StreamIdle, cancel)
	defer resp.Body.Close()

	switch {
	case !inspect || resp.StatusCode < 200 || resp.StatusCode > 299:
		p.passThrough(w, rc, resp)
	case strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream"):
		p.serveStream(ctx, cancel, w, rc, resp, pc)
	default:
		p.serveJSON(ctx, w, rc, resp, pc)
	}
}

func (p *Proxy) forward(ctx context.Context, r *http.Request, body []byte) (*http.Response, error) {
	u := *p.cfg.Upstream
	u.Path = strings.TrimRight(u.Path, "/") + r.URL.Path
	u.RawPath = ""
	u.RawQuery = r.URL.RawQuery
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	copyHeaders(req.Header, r.Header)
	req.Header.Del("Content-Length")
	req.Header.Set("Accept-Encoding", "identity")
	return p.client.Do(req)
}

// maxPassThroughBody bounds uninspected responses (upstream errors and count_tokens replies are
// small). They are buffered whole so an oversized or truncated body is rejected before any
// header is sent.
const maxPassThroughBody = 1 << 20

// passThrough relays an upstream response without inspecting it (non-2xx or count_tokens).
func (p *Proxy) passThrough(w http.ResponseWriter, rc *http.ResponseController, resp *http.Response) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxPassThroughBody+1))
	if err != nil || len(raw) > maxPassThroughBody {
		p.log.Warn("upstream body unreadable or too large", "err", err)
		p.fail(w, rc, http.StatusBadGateway, "upstream response rejected")
		return
	}
	p.writeBuffered(w, rc, resp, raw)
}

// writeBuffered sends a fully buffered body with the upstream status and filtered headers.
func (p *Proxy) writeBuffered(w http.ResponseWriter, rc *http.ResponseController, resp *http.Response, body []byte) {
	copyHeaders(w.Header(), resp.Header)
	dropRepresentationHeaders(w.Header())
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	setDeadline(rc.SetWriteDeadline, p.cfg.WriteTimeout)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

func (p *Proxy) serveJSON(ctx context.Context, w http.ResponseWriter, rc *http.ResponseController, resp *http.Response, pc policy.Context) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxBody+1))
	if err != nil || int64(len(raw)) > p.cfg.MaxBody {
		p.log.Warn("upstream body unreadable or too large", "err", err)
		p.fail(w, rc, http.StatusBadGateway, "upstream response rejected")
		return
	}
	out, err := p.rewriteMessage(ctx, pc, raw)
	if err != nil {
		p.log.Warn("upstream response rejected", "err", err)
		p.fail(w, rc, http.StatusBadGateway, "upstream response rejected")
		return
	}
	p.writeBuffered(w, rc, resp, out)
}

// fail sends a proxy-generated JSON error under a write deadline.
func (p *Proxy) fail(w http.ResponseWriter, rc *http.ResponseController, status int, msg string) {
	setDeadline(rc.SetWriteDeadline, p.cfg.WriteTimeout)
	writeJSONError(w, status, msg)
}

// userContext collects user-role text from the whole conversation, excluding tool results.
func userContext(body []byte) (policy.Context, error) {
	var req struct {
		Messages []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return policy.Context{}, err
	}
	var pc policy.Context
	for _, m := range req.Messages {
		if m.Role != "user" {
			continue
		}
		var s string
		if json.Unmarshal(m.Content, &s) == nil {
			pc.UserText = append(pc.UserText, s)
			continue
		}
		var blocks []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &blocks); err != nil {
			return policy.Context{}, err
		}
		for _, b := range blocks {
			if b.Type == "text" {
				pc.UserText = append(pc.UserText, b.Text)
			}
		}
	}
	return pc, nil
}

// notice is the fixed replacement text. It never echoes arguments or the tool name.
func notice(d policy.Decision) string {
	rule := sanitizeRule(d.Rule)
	if d.Verdict == policy.Ask {
		return "[agent-guard] A tool call requires approval and was not executed (rule: " + rule + "). Ask the user to approve it."
	}
	return "[agent-guard] A tool call was blocked by policy (rule: " + rule + ")."
}

func sanitizeRule(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 64 {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

var hopByHop = []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func copyHeaders(dst, src http.Header) {
	skip := map[string]bool{}
	for _, h := range hopByHop {
		skip[h] = true
	}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			skip[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}
	for k, vs := range src {
		if skip[http.CanonicalHeaderKey(k)] || http.CanonicalHeaderKey(k) == "Host" {
			continue
		}
		dst.Del(k)
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func dropRepresentationHeaders(h http.Header) {
	h.Del("Content-Length")
	h.Del("Etag")
	h.Del("Content-Md5")
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	b, _ := json.Marshal(map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "agent-guard: " + msg}})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// setDeadline applies now+d with a ResponseController setter, ignoring unsupported writers.
func setDeadline(set func(time.Time) error, d time.Duration) {
	_ = set(time.Now().Add(d))
}

// idleBody cancels the request context when no body bytes arrive for d.
type idleBody struct {
	rc    io.ReadCloser
	timer *time.Timer
	d     time.Duration
}

func newIdleBody(rc io.ReadCloser, d time.Duration, cancel context.CancelFunc) *idleBody {
	return &idleBody{rc: rc, d: d, timer: time.AfterFunc(d, cancel)}
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.d)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	return b.rc.Close()
}
