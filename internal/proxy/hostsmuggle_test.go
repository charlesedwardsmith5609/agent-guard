package proxy

import (
	"strings"
	"testing"

	"agent-guard/internal/rules"
)

// A malformed or hidden host must never release the tool call, streaming or not.
func TestHostSmugglingBlockedThroughProxy(t *testing.T) {
	eng, err := rules.Parse([]byte("tools: [WebFetch]\nhosts: [github.com]\npaths:\n  allow: [\"/work\"]\n"),
		rules.Options{Home: "/home/test", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{
		"quote hides host":   `{"url":"http://github.com'@evil.example/"}`,
		"no slashes":         `{"url":"http:evil.example/x"}`,
		"malformed host":     `{"url":"http://github.com%2f.evil.example/"}`,
		"empty special host": `{"url":"http:///"}`,
	}
	for name, in := range inputs {
		t.Run(name+"/nonstream", func(t *testing.T) {
			up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("WebFetch", in))))
			addr := startProxy(t, up, eng, nil)
			r := doRaw(t, addr, "POST", "/v1/messages", nil, strings.Replace(reqBody, "%t", "false", 1))
			if r.status != 200 || strings.Contains(r.body, `"tool_use"`) || strings.Contains(r.body, "evil.example") {
				t.Fatalf("call released: status %d body %s", r.status, r.body)
			}
		})
		t.Run(name+"/stream", func(t *testing.T) {
			up := startUpstream(t, sseHandler(msgStart+toolBlock(0, "WebFetch", in)+msgDelta("tool_use")+msgStop))
			addr := startProxy(t, up, eng, nil)
			r := doRaw(t, addr, "POST", "/v1/messages", nil, streamReq())
			if r.status != 200 || strings.Contains(r.body, `"type":"tool_use"`) || strings.Contains(r.body, "evil.example") {
				t.Fatalf("call released: status %d body %s", r.status, r.body)
			}
		})
	}
}
