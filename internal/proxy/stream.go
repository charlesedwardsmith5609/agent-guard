package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"agent-guard/internal/policy"
)

const (
	maxSSELine  = 1 << 20 // one line
	maxSSEEvent = 1 << 20 // all lines of one event together
)

var errEventTooLarge = errors.New("SSE event too large")

type sseEvent struct {
	raw  []byte // the event exactly as it should be re-emitted, including the blank line
	name string
	data []byte
}

type sseReader struct{ sc *bufio.Scanner }

func newSSEReader(r io.Reader) *sseReader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxSSELine)
	return &sseReader{sc: sc}
}

// next returns io.EOF only between events. An event cut off mid-way is io.ErrUnexpectedEOF.
func (s *sseReader) next() (*sseEvent, error) {
	var raw, data bytes.Buffer
	var name string
	started := false
	for s.sc.Scan() {
		line := s.sc.Bytes()
		if len(line) == 0 {
			if !started {
				continue
			}
			raw.WriteByte('\n')
			return &sseEvent{raw: raw.Bytes(), name: name, data: data.Bytes()}, nil
		}
		if raw.Len()+len(line)+1 > maxSSEEvent {
			return nil, errEventTooLarge
		}
		started = true
		raw.Write(line)
		raw.WriteByte('\n')
		if rest, ok := bytes.CutPrefix(line, []byte("event:")); ok {
			// SSE: remove at most one leading space; the rest of the value is significant.
			name = string(bytes.TrimPrefix(rest, []byte(" ")))
		}
		if rest, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			rest = bytes.TrimPrefix(rest, []byte(" "))
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.Write(rest)
		}
	}
	if err := s.sc.Err(); err != nil {
		return nil, err
	}
	if started {
		return nil, io.ErrUnexpectedEOF
	}
	return nil, io.EOF
}

var errStreamTooLarge = errors.New("stream exceeds size limit")

// capReader counts every byte read from the upstream (blank lines, comments, events alike)
// and fails once more than left bytes have been read.
type capReader struct {
	r    io.Reader
	left int64
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		return 0, errStreamTooLarge
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

type violationError struct{ msg string }

func (e *violationError) Error() string { return e.msg }

func violation(format string, a ...any) error { return &violationError{fmt.Sprintf(format, a...)} }

type writeError struct{ err error }

func (e *writeError) Error() string { return e.err.Error() }
func (e *writeError) Unwrap() error { return e.err }

type evData struct {
	Type         string `json:"type"`
	Index        *int   `json:"index"`
	ContentBlock struct {
		Type  string          `json:"type"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	} `json:"content_block"`
	Message struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	Delta struct {
		Type        string `json:"type"`
		PartialJSON string `json:"partial_json"`
		StopReason  string `json:"stop_reason"`
	} `json:"delta"`
}

// streamer rewrites one SSE response. It is owned by a single request goroutine.
type streamer struct {
	p   *Proxy
	ctx context.Context
	pc  policy.Context
	out func([]byte) error

	open      int // index of the open block, -1 if none
	holding   bool
	held      [][]byte
	heldBytes int64
	tool      policy.ToolCall
	input     bytes.Buffer

	calls, survived, replaced int
	done                      bool
}

func (p *Proxy) serveStream(ctx context.Context, cancel context.CancelFunc, w http.ResponseWriter, rc *http.ResponseController, resp *http.Response, pc policy.Context) {
	copyHeaders(w.Header(), resp.Header)
	dropRepresentationHeaders(w.Header())
	setDeadline(rc.SetWriteDeadline, p.cfg.WriteTimeout)
	w.WriteHeader(resp.StatusCode)

	out := func(b []byte) error {
		setDeadline(rc.SetWriteDeadline, p.cfg.WriteTimeout)
		if _, err := w.Write(b); err != nil {
			return &writeError{err}
		}
		if err := rc.Flush(); err != nil {
			return &writeError{err}
		}
		return nil
	}
	s := &streamer{p: p, ctx: ctx, pc: pc, out: out, open: -1}
	err := s.run(newSSEReader(&capReader{r: resp.Body, left: p.cfg.MaxBody}))
	if err == nil {
		return
	}
	cancel() // stop reading upstream; held bytes are dropped
	var we *writeError
	if errors.As(err, &we) {
		p.log.Info("client write failed", "err", err)
		return
	}
	p.log.Warn("stream rejected", "err", err)
	_ = out(frame("error", map[string]any{"type": "error", "error": map[string]string{"type": "api_error", "message": "agent-guard: response rejected (fail closed)"}}))
}

func (s *streamer) run(rd *sseReader) error {
	for !s.done {
		ev, err := rd.next()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return violation("stream ended before message_stop")
			}
			return violation("reading upstream stream: %v", err)
		}
		if err := s.handle(ev); err != nil {
			return err
		}
	}
	return nil
}

func (s *streamer) handle(ev *sseEvent) error {
	if len(bytes.TrimSpace(ev.data)) == 0 {
		return s.out(ev.raw) // comment or keep-alive without data
	}
	var d evData
	if err := json.Unmarshal(ev.data, &d); err != nil {
		return violation("invalid event JSON")
	}
	if ev.name != d.Type { // clients may dispatch on either; they must agree
		return violation("event name does not match payload type")
	}
	switch d.Type {
	case "content_block_start":
		if s.open != -1 || d.Index == nil {
			return violation("unexpected content_block_start")
		}
		s.open = *d.Index
		if d.ContentBlock.Type != "tool_use" {
			return s.out(ev.raw)
		}
		if !emptyObject(d.ContentBlock.Input) {
			return violation("tool_use start event carries input")
		}
		if int64(len(ev.raw)) > s.p.cfg.MaxHeldBytes {
			return violation("held tool call exceeds limit")
		}
		s.calls++
		s.holding = true
		s.tool = policy.ToolCall{ID: d.ContentBlock.ID, Name: d.ContentBlock.Name}
		s.input.Reset()
		s.held = [][]byte{ev.raw}
		s.heldBytes = int64(len(ev.raw))
		return nil
	case "content_block_delta":
		if d.Index == nil || *d.Index != s.open {
			return violation("content_block_delta index mismatch")
		}
		if !s.holding {
			return s.out(ev.raw)
		}
		s.heldBytes += int64(len(ev.raw))
		if s.heldBytes > s.p.cfg.MaxHeldBytes {
			return violation("held tool call exceeds limit")
		}
		s.held = append(s.held, ev.raw)
		if d.Delta.Type == "input_json_delta" {
			s.input.WriteString(d.Delta.PartialJSON)
		}
		return nil
	case "content_block_stop":
		if d.Index == nil || *d.Index != s.open {
			return violation("content_block_stop index mismatch")
		}
		if s.holding {
			return s.finishTool(ev)
		}
		s.open = -1
		return s.out(ev.raw)
	case "message_start":
		if s.open != -1 {
			return violation("message_start inside a block")
		}
		if !emptyArray(d.Message.Content) {
			return violation("message_start carries content blocks")
		}
		return s.out(ev.raw)
	case "message_delta":
		if s.open != -1 {
			return violation("message_delta inside a block")
		}
		if s.replaced > 0 && s.survived == 0 && d.Delta.StopReason == "tool_use" {
			raw, err := rewriteStopReason(ev.data)
			if err != nil {
				return violation("cannot rewrite message_delta")
			}
			return s.out(raw)
		}
		return s.out(ev.raw)
	case "message_stop":
		if s.open != -1 {
			return violation("message_stop inside a block")
		}
		s.done = true
		return s.out(ev.raw)
	case "error":
		s.done = true
		s.holding, s.held = false, nil
		return s.out(ev.raw)
	default:
		return s.out(ev.raw) // ping and unknown event types
	}
}

func (s *streamer) finishTool(stop *sseEvent) error {
	idx := s.open
	input := bytes.TrimSpace(s.input.Bytes())
	if len(input) == 0 {
		input = []byte("{}")
	}
	if !json.Valid(input) {
		return violation("assembled tool input is not valid JSON")
	}
	tc := s.tool
	tc.Input = append(json.RawMessage(nil), input...)
	held := s.held
	s.open, s.holding, s.held, s.heldBytes = -1, false, nil, 0

	dec := s.p.decide(s.ctx, s.pc, tc, true, s.calls > s.p.cfg.MaxToolCalls)
	if dec.Verdict == policy.Allow {
		s.survived++
		for _, h := range held {
			if err := s.out(h); err != nil {
				return err
			}
		}
		return s.out(stop.raw)
	}
	s.replaced++
	for _, b := range [][]byte{
		frame("content_block_start", map[string]any{"type": "content_block_start", "index": idx, "content_block": map[string]string{"type": "text", "text": ""}}),
		frame("content_block_delta", map[string]any{"type": "content_block_delta", "index": idx, "delta": map[string]string{"type": "text_delta", "text": notice(dec)}}),
		frame("content_block_stop", map[string]any{"type": "content_block_stop", "index": idx}),
	} {
		if err := s.out(b); err != nil {
			return err
		}
	}
	return nil
}

func rewriteStopReason(data []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}
	var delta map[string]json.RawMessage
	if err := json.Unmarshal(top["delta"], &delta); err != nil {
		return nil, err
	}
	delta["stop_reason"] = json.RawMessage(`"end_turn"`)
	nd, err := json.Marshal(delta)
	if err != nil {
		return nil, err
	}
	top["delta"] = nd
	b, err := json.Marshal(top)
	if err != nil {
		return nil, err
	}
	return frameRaw("message_delta", b), nil
}

func frame(name string, v any) []byte {
	b, _ := json.Marshal(v)
	return frameRaw(name, b)
}

func frameRaw(name string, data []byte) []byte {
	var sb strings.Builder
	sb.WriteString("event: " + name + "\ndata: ")
	sb.Write(data)
	sb.WriteString("\n\n")
	return []byte(sb.String())
}

// emptyObject reports whether raw is absent, null or a JSON object with no members.
func emptyObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var m map[string]json.RawMessage
	return json.Unmarshal(raw, &m) == nil && len(m) == 0
}

// emptyArray reports whether raw is absent, null or a JSON array with no elements.
func emptyArray(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var a []json.RawMessage
	return json.Unmarshal(raw, &a) == nil && len(a) == 0
}
