package rules

import (
	"context"
	"testing"

	"agent-guard/internal/policy"
)

const profileCfg = `
profiles:
  coder:
    tools: [Read, Bash]
    hosts: [github.com]
    paths:
      allow: ["/work"]
  reviewer:
    tools: [Read]
    hosts: []
    paths:
      allow: ["/work"]
agents:
  coder-1: coder
  reviewer-1: reviewer
`

func TestProfiles(t *testing.T) {
	p := newPolicy(t, profileCfg)
	read := policy.ToolCall{Name: "Read", Input: []byte(`{"file_path":"/work/a.go"}`)}
	bash := policy.ToolCall{Name: "Bash", Input: []byte(`{"command":"pwd"}`)}

	t.Run("known profile", func(t *testing.T) {
		d, err := p.Decide(context.Background(), policy.Context{AgentID: "coder-1"}, bash)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Allow || d.Profile != "coder" {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("known profile is stricter", func(t *testing.T) {
		d, err := p.Decide(context.Background(), policy.Context{AgentID: "reviewer-1"}, bash)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Block || d.Rule != RuleToolNotDeclared || d.Profile != "reviewer" {
			t.Fatalf("got %+v", d)
		}
		d, err = p.Decide(context.Background(), policy.Context{AgentID: "reviewer-1"}, read)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Allow || d.Profile != "reviewer" {
			t.Fatalf("read got %+v", d)
		}
	})
	t.Run("unknown identity", func(t *testing.T) {
		d, err := p.Decide(context.Background(), policy.Context{AgentID: "stranger"}, read)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Block || d.Rule != RuleProfileUnknown || d.Profile != "" {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("malformed identity", func(t *testing.T) {
		d, err := p.Decide(context.Background(), policy.Context{AgentIDRejected: true}, read)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Block || d.Rule != RuleProfileUnknown {
			t.Fatalf("got %+v", d)
		}
	})
	t.Run("missing identity", func(t *testing.T) {
		d, err := p.Decide(context.Background(), policy.Context{}, read)
		if err != nil {
			t.Fatal(err)
		}
		if d.Verdict != policy.Block || d.Rule != RuleProfileMissing || d.Profile != "" {
			t.Fatalf("got %+v", d)
		}
	})
}

func TestSinglePolicyRecordsDefaultProfile(t *testing.T) {
	p := newPolicy(t, baseCfg)
	d, err := p.Decide(context.Background(), policy.Context{}, policy.ToolCall{Name: "Read", Input: []byte(`{"file_path":"/work/proj/a.go"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if d.Verdict != policy.Allow || d.Profile != DefaultProfile {
		t.Fatalf("got %+v", d)
	}
}

func TestProfileConfigRejectsUnknownTarget(t *testing.T) {
	_, err := ParsePolicy([]byte(`
profiles:
  coder:
    tools: []
    hosts: []
    paths:
      allow: []
agents:
  coder-1: missing
`), Options{Home: "/home/test", Workdir: "/work"})
	if err == nil {
		t.Fatal("expected an unknown profile to fail at load")
	}
}

func newPolicy(t *testing.T, cfg string) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(cfg), Options{Home: "/home/test", Workdir: "/work"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
