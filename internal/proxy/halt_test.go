package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-guard/internal/audit"
	"agent-guard/internal/halt"
	"agent-guard/internal/rules"
)

func TestHaltBlocksCallAfterFileChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "halt")
	if err := os.WriteFile(path, []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sw := halt.New(path)
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`))))
	var buf bytes.Buffer
	lg := audit.NewWriter(&buf, audit.Options{})
	t.Cleanup(func() { lg.Close(context.Background()) })
	addr, _ := startProxyObs(t, up, decFunc(byName), func(c *Config) {
		c.Audit = lg
		c.Halt = sw
	})
	body := strings.Replace(reqBody, "%t", "false", 1)

	allowed := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if allowed.status != 200 || !strings.Contains(allowed.body, "KEEP") {
		t.Fatalf("running control should allow the call: %d %s", allowed.status, allowed.body)
	}

	for _, tc := range []struct{ name, text string }{{"halted", "halted\n"}, {"corrupt", "not-a-token"}, {"missing", ""}} {
		if tc.text == "" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else {
			writeControl(t, path, tc.text)
		}
		r := doRaw(t, addr, "POST", "/v1/messages", nil, body)
		if r.status != 503 || strings.Contains(r.body, "KEEP") {
			t.Fatalf("%s control should refuse the request: %d %s", tc.name, r.status, r.body)
		}
	}

	log := buf.String()
	for _, want := range []string{`"event":"halt"`, `"decision":"HALT"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit log missing %s:\n%s", want, log)
		}
	}
}

// TestHaltRaceDuringTraffic hammers the control file while requests are in flight.
// The -race detector checks the single mutex that owns halt state. After the
// hammer stops, a halted file must still block the next call inside the
// connection deadline.
func TestHaltRaceDuringTraffic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "halt")
	if err := os.WriteFile(path, []byte("running\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sw := halt.New(path)
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`))))
	var buf bytes.Buffer
	lg := audit.NewWriter(&buf, audit.Options{})
	t.Cleanup(func() { lg.Close(context.Background()) })
	addr, _ := startProxyObs(t, up, decFunc(byName), func(c *Config) {
		c.Audit = lg
		c.Halt = sw
	})
	body := strings.Replace(reqBody, "%t", "false", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := []byte("running\n")
			if i%2 == 1 {
				token = []byte("halted\n")
			}
			for n := 0; ctx.Err() == nil; n++ {
				// Replace the file atomically: a plain write is truncate-then-write, and a
				// read in between sees an empty file (a false halt).
				tmp := fmt.Sprintf("%s.tmp%d", path, i)
				if os.WriteFile(tmp, token, 0o600) == nil {
					_ = os.Rename(tmp, path)
				}
			}
		}(i)
	}
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				req, err := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/messages", strings.NewReader(body))
				if err != nil {
					return
				}
				resp, err := client.Do(req)
				if err != nil {
					continue
				}
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()

	writeControl(t, path, "halted\n")
	blocked := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if blocked.status != 503 || strings.Contains(blocked.body, "KEEP") {
		t.Fatalf("after the race, a halted file must refuse the next request: %d %s", blocked.status, blocked.body)
	}
}

func writeControl(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func countKind(obs *recObs, kind string) int {
	n := 0
	for _, e := range obs.snapshot() {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// A resume whose audit record failed must not take effect: the next calls stay
// blocked until a record is written, and only then does the proxy resume.
func TestResumeNeedsItsAuditRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "halt")
	writeControl(t, path, "halted\n")
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`))))
	addr, obs := startProxyObs(t, up, decFunc(byName), func(c *Config) { c.Halt = halt.New(path) })
	body := strings.Replace(reqBody, "%t", "false", 1)
	call := func() string { return doRaw(t, addr, "POST", "/v1/messages", nil, body).body }

	if r := doRaw(t, addr, "POST", "/v1/messages", nil, body); r.status != 503 {
		t.Fatalf("halted: %d %s", r.status, r.body)
	}
	writeControl(t, path, "running\n")
	obs.setErr(errors.New("disk full"))
	for i := 0; i < 2; i++ {
		r := doRaw(t, addr, "POST", "/v1/messages", nil, body)
		if r.status != 503 || strings.Contains(r.body, "KEEP") {
			t.Fatalf("call %d with a failed resume record must be refused: %d %s", i, r.status, r.body)
		}
	}
	if n := countKind(obs, "resume"); n != 2 {
		t.Fatalf("each call should retry the resume record, got %d attempts", n)
	}
	obs.setErr(nil)
	if b := call(); !strings.Contains(b, "KEEP") {
		t.Fatalf("resume should take effect once recorded: %s", b)
	}
	if b := call(); !strings.Contains(b, "KEEP") {
		t.Fatalf("still running: %s", b)
	}
	if n := countKind(obs, "resume"); n != 3 {
		t.Fatalf("resume records = %d, want 3 (two failed, one written)", n)
	}
}

// A halt whose record failed still refuses the call (fail-closed:audit), and the
// halt is recorded on a later call.
func TestHaltRecordFailureFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "halt")
	writeControl(t, path, "running\n")
	up := startUpstream(t, jsonHandler(msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`))))
	addr, obs := startProxyObs(t, up, decFunc(byName), func(c *Config) { c.Halt = halt.New(path) })
	body := strings.Replace(reqBody, "%t", "false", 1)
	call := func() string { return doRaw(t, addr, "POST", "/v1/messages", nil, body).body }

	if b := call(); !strings.Contains(b, "KEEP") {
		t.Fatalf("running: %s", b)
	}
	writeControl(t, path, "halted\n")
	obs.setErr(errors.New("disk full"))
	if r := doRaw(t, addr, "POST", "/v1/messages", nil, body); r.status != 503 || strings.Contains(r.body, "KEEP") {
		t.Fatalf("failed halt record must refuse: %d %s", r.status, r.body)
	}
	obs.setErr(nil)
	if r := doRaw(t, addr, "POST", "/v1/messages", nil, body); r.status != 503 || strings.Contains(r.body, "KEEP") {
		t.Fatalf("halted: %d %s", r.status, r.body)
	}
	if n := countKind(obs, "halt"); n != 2 {
		t.Fatalf("halt records = %d, want 2 (one failed, one written)", n)
	}
}

// A halted proxy sends nothing upstream. The halted request is awaited, then an
// allowed sentinel goes through the same proxy; the upstream's log must hold only
// the sentinel.
func TestHaltStopsUpstreamTraffic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "halt")
	writeControl(t, path, "halted\n")
	var mu sync.Mutex
	var seen []string
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("X-Marker"))
		mu.Unlock()
		jsonHandler(msgJSON("tool_use", tu("ok_tool", `{"a":"KEEP"}`)))(w, r)
	})
	addr := startProxy(t, up, decFunc(byName), func(c *Config) { c.Halt = halt.New(path) })
	body := strings.Replace(reqBody, "%t", "false", 1)

	for _, p := range []string{"/v1/messages", "/v1/messages/count_tokens"} {
		r := doRaw(t, addr, "POST", p, map[string]string{"X-Marker": "halted"}, body)
		if r.status != 503 || strings.Contains(r.body, "KEEP") {
			t.Fatalf("%s while halted: %d %s", p, r.status, r.body)
		}
	}
	writeControl(t, path, "running\n")
	r := doRaw(t, addr, "POST", "/v1/messages", map[string]string{"X-Marker": "sentinel"}, body)
	if r.status != 200 || !strings.Contains(r.body, "KEEP") {
		t.Fatalf("sentinel: %d %s", r.status, r.body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "sentinel" {
		t.Fatalf("upstream saw %q, want only the sentinel", seen)
	}
}

// A halt that lands while the upstream response is in flight still refuses the
// tool call, is audited as a refusal, and carries the agent's profile.
func TestHaltDuringRequestRefusesToolCall(t *testing.T) {
	pol, err := rules.ParsePolicy([]byte(profileYAML), rules.Options{Home: "/home/test", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "halt")
	writeControl(t, path, "running\n")
	up := startUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		writeControl(t, path, "halted\n") // the operator halts while the model is answering
		jsonHandler(msgJSON("tool_use", tu("Read", `{"file_path":"/work/a.go"}`)))(w, r)
	})
	var buf bytes.Buffer
	lg := audit.NewWriter(&buf, audit.Options{})
	t.Cleanup(func() { lg.Close(context.Background()) })
	addr, _ := startProxyObs(t, up, pol, func(c *Config) {
		c.Audit = lg
		c.Halt = halt.New(path)
	})
	r := doRaw(t, addr, "POST", "/v1/messages", map[string]string{headerAgentID: "coder-1"}, strings.Replace(reqBody, "%t", "false", 1))
	if r.status != 200 || !strings.Contains(r.body, "rule: halt") || strings.Contains(r.body, `"tool_use"`) {
		t.Fatalf("tool call should be refused: %d %s", r.status, r.body)
	}
	var refusal map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("audit line: %v %s", err, line)
		}
		if m["event"] == "refusal" {
			refusal = m
		}
	}
	if refusal == nil || refusal["rule"] != "halt" || refusal["profile"] != "coder" || refusal["agent"] != "coder-1" {
		t.Fatalf("refusal record = %v\n%s", refusal, buf.String())
	}
}
