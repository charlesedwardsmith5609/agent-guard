package proxy

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func streamReq() string { return strings.Replace(reqBody, "%t", "true", 1) }

func TestStream(t *testing.T) {
	head := msgStart
	tail := func(stop string) string { return msgDelta(stop) + msgStop }
	cases := []struct {
		name     string
		upstream string
		mod      func(*Config)
		want     []string
		notWant  []string
	}{
		{name: "text only", upstream: head + textBlock(0, "hello") + tail("end_turn"),
			want: []string{"hello", "message_stop", `"stop_reason":"end_turn"`}},
		{name: "allow", upstream: head + toolBlock(0, "ok_tool", `{"a":"KEEP"}`) + tail("tool_use"),
			want: []string{"KEEP", `"type":"tool_use"`, `"stop_reason":"tool_use"`, "message_stop"}},
		{name: "block", upstream: head + toolBlock(0, "bad_tool", `{"a":"SECRET"}`) + tail("tool_use"),
			want: []string{"blocked by policy (rule: r-bad)", `"stop_reason":"end_turn"`, "message_stop"}, notWant: []string{"SECRET", "tool_use"}},
		{name: "ask", upstream: head + toolBlock(0, "ask_tool", `{"a":"SECRET"}`) + tail("tool_use"),
			want: []string{"requires approval", `"stop_reason":"end_turn"`}, notWant: []string{"SECRET", "tool_use"}},
		{name: "mixed", upstream: head + toolBlock(0, "ok_tool", `{"a":"KEEP"}`) + toolBlock(1, "bad_tool", `{"a":"SECRET"}`) + tail("tool_use"),
			want: []string{"KEEP", "blocked by policy", `"stop_reason":"tool_use"`}, notWant: []string{"SECRET"}},
		{name: "split input deltas", upstream: head + toolBlock(0, "bad_tool", `{"a":"SEC`, `RET"}`) + tail("tool_use"),
			want: []string{"blocked by policy"}, notWant: []string{"SECRET", "SEC"}},
		{name: "decider error", upstream: head + toolBlock(0, "err_tool", `{"a":"SECRET"}`) + tail("tool_use"),
			want: []string{"blocked by policy"}, notWant: []string{"SECRET"}},
		{name: "empty input", upstream: head + toolBlock(0, "ok_tool") + tail("tool_use"),
			want: []string{`"type":"tool_use"`}},
		{name: "too many calls", upstream: head + toolBlock(0, "ok_tool", `{}`) + toolBlock(1, "ok_tool", `{"a":"SECRET"}`) + tail("tool_use"),
			mod:  func(c *Config) { c.MaxToolCalls = 1 },
			want: []string{"fail-closed:too-many-calls", `"stop_reason":"tool_use"`}, notWant: []string{"SECRET"}},
		{name: "ping and comment pass through", upstream: head + ": keepalive\n\n" + ev("ping", "") + textBlock(0, "x") + tail("end_turn"),
			want: []string{"keepalive", "ping", "message_stop"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := startUpstream(t, sseHandler(tc.upstream))
			addr := startProxy(t, up, decFunc(byName), tc.mod)
			r := doRaw(t, addr, "POST", "/v1/messages", nil, streamReq())
			if r.status != 200 {
				t.Fatalf("status %d: %s", r.status, r.body)
			}
			if strings.Contains(r.body, "event: error") {
				t.Fatalf("unexpected error event: %s", r.body)
			}
			for _, w := range tc.want {
				if !strings.Contains(r.body, w) {
					t.Errorf("missing %q in:\n%s", w, r.body)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(r.body, w) {
					t.Errorf("unexpected %q in:\n%s", w, r.body)
				}
			}
		})
	}
}

func TestStreamViolations(t *testing.T) {
	big := `{"a":"` + strings.Repeat("A", 200) + `"}`
	cases := []struct {
		name     string
		upstream string
		mod      func(*Config)
	}{
		{"malformed event JSON", msgStart + "event: content_block_delta\ndata: {nope\n\n", nil},
		{"overlapping blocks", msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SECRET"}`) + textBlock(1, "x"), nil},
		{"duplicate start", msgStart + textBlock(0, "x")[:strings.Index(textBlock(0, "x"), "event: content_block_delta")] + toolStart(0, "ok_tool"), nil},
		{"index mismatch", msgStart + toolStart(0, "ok_tool") + toolDelta(1, `{"a":"SECRET"}`), nil},
		{"stop index mismatch", msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SECRET"}`) + blockStop(3), nil},
		{"truncated mid tool", msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SECRET"}`), nil},
		{"truncated mid event", msgStart + "event: content_block_start\ndata: {\"type\":", nil},
		{"truncated before message_stop", msgStart + textBlock(0, "x") + msgDelta("end_turn"), nil},
		{"invalid assembled JSON", msgStart + toolBlock(0, "ok_tool", `{"a":"SECRET`) + msgDelta("tool_use") + msgStop, nil},
		{"held bytes overflow", msgStart + toolBlock(0, "ok_tool", big) + msgDelta("tool_use") + msgStop, func(c *Config) { c.MaxHeldBytes = 400 }},
		{"start event alone exceeds held limit", msgStart + toolBlock(0, "ok_tool", `{"a":"SECRET"}`) + msgDelta("tool_use") + msgStop, func(c *Config) { c.MaxHeldBytes = 100 }},
		{"start event carries input", msgStart + ev("content_block_start", `,"index":0,"content_block":{"type":"tool_use","id":"t","name":"ok_tool","input":{"a":"SECRET"}}`) + blockStop(0) + msgDelta("tool_use") + msgStop, nil},
		{"message_start carries tool block", `event: message_start
data: {"type":"message_start","message":{"id":"m","content":[{"type":"tool_use","id":"t","name":"ok_tool","input":{"a":"SECRET"}}]}}

` + textBlock(0, "x") + msgDelta("end_turn") + msgStop, nil},
		{"event of many sub-limit lines", msgStart + strings.Repeat(": "+strings.Repeat("x", 100000)+"\n", 12) + "\n" + textBlock(0, "x") + msgDelta("end_turn") + msgStop, nil},
		{"message_stop while holding", msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SECRET"}`) + msgStop, nil},
		{"message_delta while holding", msgStart + toolStart(0, "ok_tool") + toolDelta(0, `{"a":"SECRET"}`) + msgDelta("tool_use") + msgStop, nil},
		{"event name hides a tool block under ping", msgStart + "event: ping\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"t\",\"name\":\"bad_tool\",\"input\":{}}}\n\n" + toolDelta(0, `{"a":"SECRET"}`) + blockStop(0) + msgDelta("tool_use") + msgStop, nil},
		{"event name mismatch on a delta", msgStart + toolStart(0, "ok_tool") + "event: ping\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n" + blockStop(0) + msgDelta("tool_use") + msgStop, nil},
		{"missing event name", msgStart + "data: {\"type\":\"ping\"}\n\n" + textBlock(0, "x") + msgDelta("end_turn") + msgStop, nil},
		{"total stream size over limit (text)", msgStart + repeatBlocks(60, func(i int) string { return textBlock(i, strings.Repeat("t", 200)) }) + msgDelta("end_turn") + msgStop, func(c *Config) { c.MaxBody = 8000 }},
		{"total stream size over limit (blocked calls shrink to notices)", msgStart + repeatBlocks(60, func(i int) string { return toolBlock(i, "bad_tool", `{"a":"x"}`) }) + msgDelta("tool_use") + msgStop, func(c *Config) { c.MaxBody = 8000; c.MaxToolCalls = 1000 }},
		{"line too long", msgStart + "data: " + strings.Repeat("x", maxSSELine+10) + "\n\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := startUpstream(t, sseHandler(tc.upstream))
			addr := startProxy(t, up, decFunc(byName), tc.mod)
			r := doRaw(t, addr, "POST", "/v1/messages", nil, streamReq())
			if !strings.Contains(r.body, "event: error") {
				t.Errorf("no error event:\n%.400s", r.body)
			}
			if strings.Contains(r.body, "message_stop") {
				t.Errorf("message_stop forwarded after violation")
			}
			if strings.Contains(r.body, "SECRET") {
				t.Errorf("held bytes leaked")
			}
		})
	}
}

// TestStreamLiveDelivery proves text reaches the client while the upstream is still open.
func TestStreamLiveDelivery(t *testing.T) {
	release := make(chan struct{})
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, msgStart+textBlock(0, "hello-live"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		io.WriteString(w, msgDelta("end_turn")+msgStop)
	})
	addr := startProxy(t, up, decFunc(byName), nil)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	conn := dial(t, addr)
	sendRequest(t, conn, "POST", "/v1/messages", nil, streamReq())
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got strings.Builder
	buf := make([]byte, 4096)
	for !strings.Contains(got.String(), "hello-live") {
		n, err := resp.Body.Read(buf) // blocks until data or the connection deadline
		got.Write(buf[:n])
		if err != nil {
			t.Fatalf("stream ended before live text arrived: %v\n%s", err, got.String())
		}
	}
	if strings.Contains(got.String(), "message_stop") {
		t.Fatal("received the end of the stream before upstream finished")
	}
	close(release)
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rest), "message_stop") {
		t.Errorf("missing message_stop: %s", rest)
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	release := make(chan struct{})
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, msgStart)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.StreamIdle = 150 * time.Millisecond })
	t.Cleanup(func() { close(release) })
	r := doRaw(t, addr, "POST", "/v1/messages", nil, streamReq())
	if !strings.Contains(r.body, "event: error") || strings.Contains(r.body, "message_stop") {
		t.Errorf("expected error event, got:\n%s", r.body)
	}
}

func repeatBlocks(n int, f func(i int) string) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteString(f(i))
	}
	return sb.String()
}
