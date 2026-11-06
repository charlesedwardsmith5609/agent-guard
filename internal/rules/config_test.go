package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"agent-guard/internal/policy"
)

func TestParseConfig(t *testing.T) {
	ok := func(extra string) string {
		return "tools: [Bash]\nhosts: [github.com]\npaths:\n  allow: [/work]\n" + extra
	}
	cases := []struct {
		name    string
		cfg     string
		wantErr string // substring; empty means success
	}{
		{"valid", ok(""), ""},
		{"valid with empty lists", "tools: []\nhosts: []\npaths:\n  allow: []\n", ""},
		{"sensitive overrides", ok("sensitive:\n  ssh: block\n  dotenv: ask\n  metadata: BLOCK\n"), ""},
		{"empty file", "", "empty"},
		{"comment only", "# nothing\n", "empty"},
		{"unknown top-level key", ok("extra: 1\n"), "field extra"},
		{"unknown nested key", "tools: []\nhosts: []\npaths:\n  allow: []\n  nope: 1\n", "nope"},
		{"unknown sensitive class", ok("sensitive:\n  kerberos: ask\n"), "unknown sensitive class"},
		{"bad sensitive value", ok("sensitive:\n  ssh: allow\n"), "must be ask or block"},
		{"missing tools", "hosts: []\npaths:\n  allow: []\n", "required"},
		{"missing hosts", "tools: []\npaths:\n  allow: []\n", "required"},
		{"missing paths", "tools: []\nhosts: []\n", "required"},
		{"missing paths.allow", "tools: []\nhosts: []\npaths:\n  workdir: /w\n", "required"},
		{"invalid yaml", "tools: [", "config"},
		{"host with path", "tools: []\nhosts: [evil.com/x]\npaths:\n  allow: []\n", "invalid host"},
		{"host with port", "tools: []\nhosts: ['a.com:80']\npaths:\n  allow: []\n", "invalid host"},
		{"bare wildcard host", "tools: []\nhosts: ['*']\npaths:\n  allow: []\n", "invalid host"},
		{"relative workdir", "tools: []\nhosts: []\npaths:\n  workdir: rel\n  allow: []\n", "workdir"},
		{"relative allow", "tools: []\nhosts: []\npaths:\n  allow: [rel/dir]\n", "paths.allow"},
		{"bare star tool", "tools: ['*']\nhosts: []\npaths:\n  allow: []\n", "at least 3"},
		{"short tool prefix", "tools: ['ab*']\nhosts: []\npaths:\n  allow: []\n", "at least 3"},
		{"mid-string star", "tools: ['mc*p']\nhosts: []\npaths:\n  allow: []\n", "only allowed at the end"},
		{"empty tool name", "tools: ['']\nhosts: []\npaths:\n  allow: []\n", "invalid tool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfg), Options{Home: "/home/test", Workdir: "/cwd"})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatal("expected an error")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestEmptyListsAllowNothing(t *testing.T) {
	e := newEngine(t, "tools: []\nhosts: []\npaths:\n  allow: []\n")
	got := decide(t, e, "Read", `{"file_path":"/tmp/x"}`)
	if got.Verdict != policy.Block || got.Rule != RuleToolNotDeclared {
		t.Errorf("got %+v", got)
	}
	e = newEngine(t, "tools: [Read]\nhosts: []\npaths:\n  allow: []\n")
	if got := decide(t, e, "Read", `{"file_path":"/tmp/x"}`); got.Rule != RulePathOutOfScope {
		t.Errorf("empty paths.allow must allow no paths: %+v", got)
	}
}

func TestWorkdirDefaultsAndTildeEntries(t *testing.T) {
	e := newEngine(t, "tools: [Read]\nhosts: []\npaths:\n  allow: [/cwd, '~/proj']\n")
	for path, want := range map[string]policy.Verdict{
		"rel/file":          policy.Allow, // resolves against the default workdir /cwd
		"/home/test/proj/a": policy.Allow,
		"/home/test/other":  policy.Block,
	} {
		if got := decide(t, e, "Read", `{"file_path":"`+path+`"}`); got.Verdict != want {
			t.Errorf("%s: got %+v want %s", path, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
	f := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(f, []byte("tools: [Bash]\nhosts: []\npaths:\n  allow: [/tmp]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err != nil {
		t.Fatal(err)
	}
}
