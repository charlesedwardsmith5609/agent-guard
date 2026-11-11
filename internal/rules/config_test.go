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
		{"second document", ok("---\ntools: []\nhosts: []\npaths:\n  allow: []\n"), "exactly one"},
		{"malformed second document", ok("---\n: : :\n"), "exactly one"},
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
		{"valid canaries and forum_tools", ok("canaries: [\"AG_CANARY_DEPLOY_00\"]\nforum_tools: [\"mcp__slack__*\"]\n"), ""},
		{"canary too short", ok("canaries: [\"short-canary-1\"]\n"), "16"},
		{"canary leading space", ok("canaries: [\" AG_CANARY_DEPLOY_0\"]\n"), "whitespace"},
		{"canary trailing space", ok("canaries: [\"AG_CANARY_DEPLOY_0 \"]\n"), "whitespace"},
		{"empty canaries list", ok("canaries: []\n"), ""},
		{"too many canaries", ok("canaries: [" + manyCanariesYAML(65) + "]\n"), "at most 64 canaries"},
		{"forum_tools short prefix", ok("forum_tools: ['ab*']\n"), "at least 3"},
		{"empty forum_tools", ok("forum_tools: []\n"), ""},
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

func TestLoadRejectsHugeFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.yaml")
	body := "tools: []\nhosts: []\npaths:\n  allow: []\n# " + strings.Repeat("x", maxConfigBytes) + "\n"
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func manyCanariesYAML(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		// 16-byte unique tokens: AG_CANARY_ + zero-padded index
		b.WriteString(`"`)
		b.WriteString("AG_CANARY_")
		b.WriteString(strings.Repeat("0", 6-len(itoa(i))))
		b.WriteString(itoa(i))
		b.WriteString(`"`)
	}
	return b.String()
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for i > 0 {
		d = append([]byte{byte('0' + i%10)}, d...)
		i /= 10
	}
	return string(d)
}

func TestCanariesCopy(t *testing.T) {
	e := newEngine(t, okCfg(`canaries: ["AG_CANARY_DEPLOY_00"]`))
	got := e.Canaries()
	if len(got) != 1 || got[0] != "AG_CANARY_DEPLOY_00" {
		t.Fatalf("Canaries = %v", got)
	}
	got[0] = "mutated-not-engine"
	if e.Canaries()[0] != "AG_CANARY_DEPLOY_00" {
		t.Fatal("Canaries must return a copy")
	}
}

func okCfg(extra string) string {
	return "tools: [Bash]\nhosts: [github.com]\npaths:\n  allow: [/work]\n" + extra
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
