package proxy

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"agent-guard/internal/policy"
)

func startProxyTelemetry(t *testing.T, up string, d policy.Decider, mod func(*Config)) (string, *recObs, *recObs) {
	t.Helper()
	tel := &recObs{}
	addr, aud := startProxyObs(t, up, d, func(c *Config) {
		c.Telemetry = tel
		if mod != nil {
			mod(c)
		}
	})
	return addr, aud, tel
}

type want struct {
	tool    string
	verdict policy.Verdict
	rule    string
}

func TestObserverSeesEveryDecision(t *testing.T) {
	twoOK := msgJSON("tool_use", tu("ok_tool", `{}`), tu("bad_tool", `{"a":"x"}`), tu("ask_tool", `{}`), tu("err_tool", `{}`))
	sseCalls := msgStart + toolBlock(0, "ok_tool", `{}`) + toolBlock(1, "bad_tool", `{"a":"x"}`) + toolBlock(2, "ask_tool", `{}`) +
		toolBlock(3, "err_tool", `{}`) + msgDelta("tool_use") + msgStop
	all := []want{
		{"ok_tool", policy.Allow, "r-ok"}, {"bad_tool", policy.Block, "r-bad"},
		{"ask_tool", policy.Ask, "r-ask"}, {"err_tool", policy.Block, "fail-closed:error"},
	}
	cases := []struct {
		name   string
		up     func() string
		stream bool
		mod    func(*Config)
		want   []want
	}{
		{"non-stream", func() string { return twoOK }, false, nil, all},
		{"stream", func() string { return sseCalls }, true, nil, all},
		{"non-stream call limit", func() string { return twoOK }, false, func(c *Config) { c.MaxToolCalls = 2 },
			[]want{all[0], all[1], {"ask_tool", policy.Block, "fail-closed:too-many-calls"}, {"err_tool", policy.Block, "fail-closed:too-many-calls"}}},
		{"stream call limit", func() string { return sseCalls }, true, func(c *Config) { c.MaxToolCalls = 2 },
			[]want{all[0], all[1], {"ask_tool", policy.Block, "fail-closed:too-many-calls"}, {"err_tool", policy.Block, "fail-closed:too-many-calls"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := jsonHandler(tc.up())
			if tc.stream {
				h = sseHandler(tc.up())
			}
			addr, aud, tel := startProxyTelemetry(t, startUpstream(t, h), decFunc(byName), tc.mod)
			if r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1)); r.status != 200 {
				t.Fatalf("status %d: %s", r.status, r.body)
			}
			for name, o := range map[string]*recObs{"audit": aud, "telemetry": tel} {
				got := o.snapshot()
				if len(got) != len(tc.want) {
					t.Fatalf("%s saw %d events, want %d", name, len(got), len(tc.want))
				}
				for i, w := range tc.want {
					e := got[i]
					if e.Call.Name != w.tool || e.Decision.Verdict != w.verdict || e.Decision.Rule != w.rule {
						t.Errorf("%s event %d = %s %s/%s, want %s %s/%s", name, i, e.Call.Name, e.Decision.Verdict, e.Decision.Rule, w.tool, w.verdict, w.rule)
					}
					if e.Stream != tc.stream {
						t.Errorf("%s event %d: stream = %v", name, i, e.Stream)
					}
					if e.End.Before(e.Start) || e.Start.IsZero() {
						t.Errorf("%s event %d: bad times %v..%v", name, i, e.Start, e.End)
					}
					if len(e.Call.Input) == 0 {
						t.Errorf("%s event %d: no input recorded", name, i)
					}
				}
			}
		})
	}
}

func TestAuditFailureBlocksAllow(t *testing.T) {
	calls := tu("ok_tool", `{"a":"KEEP"}`) + "," + tu("bad_tool", `{}`) + "," + tu("ask_tool", `{}`)
	sse := msgStart + toolBlock(0, "ok_tool", `{"a":"KEEP"}`) + toolBlock(1, "bad_tool", `{}`) + toolBlock(2, "ask_tool", `{}`) + msgDelta("tool_use") + msgStop
	for _, stream := range []bool{false, true} {
		name := map[bool]string{false: "non-stream", true: "stream"}[stream]
		t.Run(name, func(t *testing.T) {
			h := jsonHandler(msgJSON("tool_use", calls))
			if stream {
				h = sseHandler(sse)
			}
			addr, aud, tel := startProxyTelemetry(t, startUpstream(t, h), decFunc(byName), nil)
			aud.setErr(errors.New("disk full"))
			r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
			if r.status != 200 {
				t.Fatalf("status %d", r.status)
			}
			if strings.Contains(r.body, "KEEP") || strings.Contains(r.body, `"tool_use"`) {
				t.Errorf("an unrecorded ALLOW was forwarded:\n%s", r.body)
			}
			if !strings.Contains(r.body, "fail-closed:audit") {
				t.Errorf("missing audit fail-closed notice:\n%s", r.body)
			}
			if !strings.Contains(r.body, "rule: r-bad") || !strings.Contains(r.body, "requires approval") {
				t.Errorf("BLOCK and ASK must be unchanged:\n%s", r.body)
			}
			got := tel.snapshot()
			if len(got) != 3 || got[0].Decision.Rule != "fail-closed:audit" || got[0].Decision.Verdict != policy.Block {
				t.Errorf("telemetry must see the final decision: %+v", got)
			}
		})
	}
}

// If the client disconnects while a decision is pending, the record is still written, with a
// context that is not cancelled.
func TestAuditSurvivesClientDisconnect(t *testing.T) {
	started := make(chan struct{})
	dec := decFunc(func(ctx context.Context, _ policy.Context, _ policy.ToolCall) (policy.Decision, error) {
		close(started)
		<-ctx.Done()
		return policy.Decision{Verdict: policy.Allow, Rule: "late"}, nil
	})
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{}`))))
	addr, aud := startProxyObs(t, up, dec, nil)
	conn := dial(t, addr)
	sendRequest(t, conn, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
	recv(t, started)
	conn.Close()

	recv(t, aud.got) // the event arrives although the client is gone
	evs := aud.snapshot()
	if len(evs) != 1 || evs[0].Decision.Verdict != policy.Block || evs[0].Decision.Rule != "fail-closed:timeout" {
		t.Fatalf("events = %+v", evs)
	}
	aud.mu.Lock()
	err := aud.ctxErr[0]
	aud.mu.Unlock()
	if err != nil {
		t.Errorf("observer context was cancelled: %v", err)
	}
}

func TestNewRequiresAudit(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	if _, err := New(Config{Upstream: u, Decider: policy.DenyAll{}}); err == nil {
		t.Fatal("expected an error without an audit observer")
	}
}
