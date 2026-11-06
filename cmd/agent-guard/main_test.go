package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	cases := []struct {
		name string
		args []string
		ok   bool
	}{
		{"config only", []string{"-config", "c.yaml"}, true},
		{"no config", nil, false},
		{"custom", []string{"-config", "c.yaml", "-max-conns", "3", "-max-inflight", "2", "-max-response", "1m"}, true},
		{"zero conns", []string{"-config", "c.yaml", "-max-conns", "0"}, false},
		{"negative inflight", []string{"-config", "c.yaml", "-max-inflight", "-1"}, false},
		{"zero response", []string{"-config", "c.yaml", "-max-response", "0s"}, false},
		{"unknown flag", []string{"-config", "c.yaml", "-nope"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOptions(tc.args, io.Discard)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// TestProductionServer builds the real server the way main does and checks the wiring.
func TestProductionServer(t *testing.T) {
	o, err := parseOptions([]string{"-config", writeConfig(t, "tools: []\nhosts: []\npaths:\n  allow: []\n"), "-listen", "127.0.0.1:0", "-upstream", "http://127.0.0.1:1"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, ln, err := newServer(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%T", ln); got != "*proxy.limitListener" {
		t.Errorf("listener is %s, want the connection-limited listener", got)
	}
	if srv.MaxHeaderBytes != 64<<10 {
		t.Errorf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	addr := ln.Addr().String()

	status := func(request string) int {
		t.Helper()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		io.WriteString(conn, request)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if got := status("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n"); got != 404 {
		t.Errorf("GET / = %d, want 404 from the proxy", got)
	}
	big := "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\nX-Big: " + strings.Repeat("a", 70<<10) + "\r\n\r\n"
	if got := status(big); got != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("oversized header = %d, want 431", got)
	}
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestBadConfigRefusesToStart(t *testing.T) {
	for name, body := range map[string]string{
		"missing keys": "tools: []\n",
		"unknown key":  "tools: []\nhosts: []\npaths:\n  allow: []\nbogus: 1\n",
		"empty":        "",
	} {
		t.Run(name, func(t *testing.T) {
			o, err := parseOptions([]string{"-config", writeConfig(t, body), "-listen", "127.0.0.1:0"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if _, ln, err := newServer(o, nil); err == nil {
				ln.Close()
				t.Fatal("expected newServer to fail")
			}
		})
	}
	o, _ := parseOptions([]string{"-config", filepath.Join(t.TempDir(), "nope.yaml")}, io.Discard)
	if _, _, err := newServer(o, nil); err == nil {
		t.Fatal("expected failure for a missing config file")
	}
}

// TestEndToEndPolicy runs a real YAML policy through the production server against a fake
// upstream that asks for three tool calls: one allowed, one needing approval, one undeclared.
func TestEndToEndPolicy(t *testing.T) {
	work := t.TempDir()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"type":"message","stop_reason":"tool_use","content":[
			{"type":"tool_use","id":"1","name":"Read","input":{"file_path":"`+filepath.Join(work, "a.txt")+`"}},
			{"type":"tool_use","id":"2","name":"Bash","input":{"command":"cat .env"}},
			{"type":"tool_use","id":"3","name":"Delete","input":{"path":"/"}}]}`)
	}))
	t.Cleanup(upstream.Close)

	cfg := writeConfig(t, "tools: [Read, Bash]\nhosts: []\npaths:\n  allow: ["+work+"]\n")
	o, err := parseOptions([]string{"-config", cfg, "-listen", "127.0.0.1:0", "-upstream", upstream.URL}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	srv, ln, err := newServer(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	body := `{"model":"m","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`
	fmt.Fprintf(conn, "POST /v1/messages HTTP/1.1\r\nHost: t\r\nConnection: close\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Content) != 3 {
		t.Fatalf("content = %+v", out.Content)
	}
	if out.Content[0].Type != "tool_use" {
		t.Errorf("Read inside scope should pass: %+v", out.Content[0])
	}
	if out.Content[1].Type != "text" || !strings.Contains(out.Content[1].Text, "requires approval") || !strings.Contains(out.Content[1].Text, "sensitive:dotenv") {
		t.Errorf("Bash cat .env should ask: %+v", out.Content[1])
	}
	if out.Content[2].Type != "text" || !strings.Contains(out.Content[2].Text, "blocked by policy") || !strings.Contains(out.Content[2].Text, "tool-not-declared") {
		t.Errorf("Delete should be blocked: %+v", out.Content[2])
	}
	if out.StopReason != "tool_use" {
		t.Errorf("stop_reason = %q; one call survived", out.StopReason)
	}
}
