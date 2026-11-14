package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"agent-guard/internal/audit"
	"agent-guard/internal/rules"
)

const profileYAML = `
profiles:
  coder:
    tools: [Read]
    hosts: []
    paths:
      workdir: /work
      allow: ["/work"]
agents:
  coder-1: coder
`

func TestProfileAuditAndHeader(t *testing.T) {
	pol, err := rules.ParsePolicy([]byte(profileYAML), rules.Options{Home: "/home/test", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	lg := audit.NewWriter(&buf, audit.Options{})
	t.Cleanup(func() { lg.Close(context.Background()) })
	seen := make(chan string, 4)
	upstream := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case seen <- r.Header.Get(headerAgentID):
		default:
		}
		jsonHandler(msgJSON("tool_use", tu("Read", `{"file_path":"/work/a.go"}`)))(w, r)
	})
	addr, _ := startProxyObs(t, upstream, pol, func(c *Config) { c.Audit = lg })
	body := strings.Replace(reqBody, "%t", "false", 1)

	ok := doRaw(t, addr, "POST", "/v1/messages", map[string]string{headerAgentID: "coder-1"}, body)
	if ok.status != 200 || !strings.Contains(ok.body, `"tool_use"`) {
		t.Fatalf("known profile should allow Read: %d %s", ok.status, ok.body)
	}
	if got := recv(t, seen); got != "" {
		t.Errorf("identity header was forwarded: %q", got)
	}

	missing := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if !strings.Contains(missing.body, "rule: profile-missing") || strings.Contains(missing.body, `"tool_use"`) {
		t.Fatalf("missing identity should deny: %s", missing.body)
	}
	unknown := doRaw(t, addr, "POST", "/v1/messages", map[string]string{headerAgentID: "stranger"}, body)
	if !strings.Contains(unknown.body, "rule: profile-unknown") {
		t.Fatalf("unknown identity should deny: %s", unknown.body)
	}
	bad := doRaw(t, addr, "POST", "/v1/messages", map[string]string{headerAgentID: "has space"}, body)
	if !strings.Contains(bad.body, "rule: profile-unknown") {
		t.Fatalf("malformed identity should deny: %s", bad.body)
	}

	var sawProfile bool
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line: %v %s", err, line)
		}
		if _, ok := m["profile"]; !ok {
			t.Fatalf("audit record has no profile field: %s", line)
		}
		sawProfile = true
		if m["rule"] == "allow" && (m["profile"] != "coder" || m["agent"] != "coder-1") {
			t.Errorf("allowed record = %v", m)
		}
		if m["rule"] == "profile-missing" && m["profile"] != "" {
			t.Errorf("missing-identity profile = %v", m["profile"])
		}
	}
	if !sawProfile {
		t.Fatal("no audit records")
	}
}

// The identity header is the proxy's own: it is removed on every forwarded path
// (including count_tokens, which is not inspected), with every duplicate value.
func TestIdentityHeaderStrippedEverywhere(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/messages/count_tokens"} {
		t.Run(path, func(t *testing.T) {
			seen := make(chan []string, 1)
			up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				seen <- r.Header.Values(headerAgentID)
				jsonHandler(msgJSON("end_turn", txt))(w, r)
			})
			addr := startProxy(t, up, decFunc(byName), nil)
			conn := dial(t, addr)
			body := strings.Replace(reqBody, "%t", "false", 1)
			io.WriteString(conn, "POST "+path+" HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
				headerAgentID+": coder-1\r\n"+headerAgentID+": admin\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := recv(t, seen); len(got) != 0 {
				t.Fatalf("identity header reached the upstream: %q", got)
			}
		})
	}
}

// With two identity headers the proxy uses the first and never the second. The test
// pins that behaviour so a change is deliberate.
func TestDuplicateIdentityHeadersUseFirst(t *testing.T) {
	pol, err := rules.ParsePolicy([]byte(profileYAML), rules.Options{Home: "/home/test", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("Read", `{"file_path":"/work/a.go"}`))))
	addr := startProxy(t, up, pol, nil)
	send := func(first, second string) string {
		conn := dial(t, addr)
		body := strings.Replace(reqBody, "%t", "false", 1)
		io.WriteString(conn, "POST /v1/messages HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"+
			headerAgentID+": "+first+"\r\n"+headerAgentID+": "+second+"\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if b := send("coder-1", "stranger"); !strings.Contains(b, `"tool_use"`) {
		t.Fatalf("first value should decide: %s", b)
	}
	if b := send("stranger", "coder-1"); !strings.Contains(b, "rule: profile-unknown") {
		t.Fatalf("a later value must not rescue an unknown first value: %s", b)
	}
}
