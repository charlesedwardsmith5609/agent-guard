package proxy

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"agent-guard/internal/audit"
	"agent-guard/internal/halt"
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

	if err := os.WriteFile(path, []byte("halted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if blocked.status != 200 || !strings.Contains(blocked.body, "rule: halt") || strings.Contains(blocked.body, "KEEP") {
		t.Fatalf("halted control should block: %d %s", blocked.status, blocked.body)
	}

	if err := os.WriteFile(path, []byte("not-a-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if !strings.Contains(corrupt.body, "rule: halt") || strings.Contains(corrupt.body, "KEEP") {
		t.Fatalf("corrupt control should fail closed: %s", corrupt.body)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	missing := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if !strings.Contains(missing.body, "rule: halt") || strings.Contains(missing.body, "KEEP") {
		t.Fatalf("missing control should fail closed: %s", missing.body)
	}

	log := buf.String()
	for _, want := range []string{`"event":"halt"`, `"decision":"HALT"`, `"event":"refusal"`, `"rule":"halt"`} {
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
			for ctx.Err() == nil {
				_ = os.WriteFile(path, token, 0o600)
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

	if err := os.WriteFile(path, []byte("halted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := doRaw(t, addr, "POST", "/v1/messages", nil, body)
	if !strings.Contains(blocked.body, "rule: halt") || strings.Contains(blocked.body, "KEEP") {
		t.Fatalf("after the race, a halted file must block the next call: %s", blocked.body)
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

	if b := call(); !strings.Contains(b, "rule: halt") {
		t.Fatalf("halted: %s", b)
	}
	writeControl(t, path, "running\n")
	obs.setErr(errors.New("disk full"))
	for i := 0; i < 2; i++ {
		b := call()
		if !strings.Contains(b, "fail-closed:audit") || strings.Contains(b, "KEEP") {
			t.Fatalf("call %d with a failed resume record must be blocked: %s", i, b)
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
	if b := call(); !strings.Contains(b, "fail-closed:audit") || strings.Contains(b, "KEEP") {
		t.Fatalf("failed halt record must refuse: %s", b)
	}
	obs.setErr(nil)
	if b := call(); !strings.Contains(b, "rule: halt") || strings.Contains(b, "KEEP") {
		t.Fatalf("halted: %s", b)
	}
	if n := countKind(obs, "halt"); n != 2 {
		t.Fatalf("halt records = %d, want 2 (one failed, one written)", n)
	}
}
