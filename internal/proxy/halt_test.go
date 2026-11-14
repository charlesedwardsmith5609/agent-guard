package proxy

import (
	"bytes"
	"context"
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
