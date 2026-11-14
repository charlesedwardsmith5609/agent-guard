package rules

import (
	"context"
	"testing"

	"agent-guard/internal/policy"
)

// Hosts in baseCfg include github.com. loopCfg also allowlists 127.0.0.1 and ::1
// so alternate spellings of an allowlisted address must match, and every other
// spelling of a different address must not.
func TestCanonicalMentionUsesStoredForm(t *testing.T) {
	e := newEngine(t, baseCfg)
	call := policy.ToolCall{Name: "WebFetch", Input: []byte(obj("url", "http://2130706433/"))}
	got, err := e.Decide(context.Background(), policy.Context{UserText: []string{"please use 127.0.0.1"}}, call)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != policy.Allow {
		t.Fatalf("canonical mention should cover the decimal spelling, got %s/%s", got.Verdict, got.Rule)
	}
	got, err = e.Decide(context.Background(), policy.Context{UserText: []string{"please use 2130706433"}}, call)
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != policy.Block || got.Rule != RuleHostNotAllowed {
		t.Fatalf("the decimal spelling is not the stored host, got %s/%s", got.Verdict, got.Rule)
	}
}

func TestHostNormalization(t *testing.T) {
	loopCfg := "tools: [WebFetch, Bash]\nhosts: [github.com, 127.0.0.1, \"::1\"]\npaths:\n  allow: [\"/work\"]\n"
	cases := []struct {
		name string
		cfg  string
		in   string
		want policy.Verdict
		rule string
	}{
		{name: "decimal blocks when not listed", in: obj("url", "http://2130706433/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "hex blocks when not listed", in: obj("url", "http://0x7f000001/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "octal blocks when not listed", in: obj("url", "http://0177.0.0.1/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "dotted hex blocks when not listed", in: obj("url", "http://0x7f.0x0.0x0.0x1/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "bracketed ipv6 blocks when not listed", in: obj("url", "http://[2001:db8::1]/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "userinfo is not the host", in: obj("url", "http://github.com@evil.com/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "userinfo with port is not the host", in: obj("url", "http://github.com:443@evil.com/x"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "userinfo before bracketed ipv6", in: obj("url", "http://github.com@[2001:db8::1]/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "trailing dot on unlisted host", in: obj("url", "http://evil.com./"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "mixed case unlisted host", in: obj("url", "http://EvIl.COM/x"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "port on unlisted host", in: obj("url", "http://evil.com:443/"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "mixed case trailing dot and port", in: obj("url", "http://EvIl.COM.:8443/x"), want: policy.Block, rule: RuleHostNotAllowed},
		{name: "decimal port still the address", in: obj("url", "http://2130706433:80/"), want: policy.Block, rule: RuleHostNotAllowed},

		{name: "allowlisted mixed case trailing dot", in: obj("url", "https://GitHub.COM./x"), want: policy.Allow, rule: "allow"},
		{name: "allowlisted with port", in: obj("url", "https://github.com:443/x"), want: policy.Allow, rule: "allow"},
		{name: "allowlisted userinfo and port", in: obj("url", "https://user:pw@github.com:443/x"), want: policy.Allow, rule: "allow"},

		{name: "decimal of allowlisted ipv4", cfg: loopCfg, in: obj("url", "http://2130706433/"), want: policy.Allow, rule: "allow"},
		{name: "hex of allowlisted ipv4", cfg: loopCfg, in: obj("url", "http://0x7f000001/"), want: policy.Allow, rule: "allow"},
		{name: "octal of allowlisted ipv4", cfg: loopCfg, in: obj("url", "http://0177.0.0.1/"), want: policy.Allow, rule: "allow"},
		{name: "dotted hex of allowlisted ipv4", cfg: loopCfg, in: obj("url", "http://0x7f.0.0.1/"), want: policy.Allow, rule: "allow"},
		{name: "bracketed ipv6 allowlisted", cfg: loopCfg, in: obj("url", "http://[::1]/"), want: policy.Allow, rule: "allow"},
		{name: "expanded ipv6 same as compressed", cfg: loopCfg, in: obj("url", "http://[0:0:0:0:0:0:0:1]/"), want: policy.Allow, rule: "allow"},
		{name: "ipv4 mapped to allowlisted ipv4", cfg: loopCfg, in: obj("url", "http://[::ffff:127.0.0.1]/"), want: policy.Allow, rule: "allow"},
		{name: "bracketed ipv6 with port", cfg: loopCfg, in: obj("url", "http://[::1]:443/"), want: policy.Allow, rule: "allow"},
		{name: "other ipv6 still blocked", cfg: loopCfg, in: obj("url", "http://[2001:db8::1]/"), want: policy.Block, rule: RuleHostNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if cfg == "" {
				cfg = baseCfg
			}
			e := newEngine(t, cfg)
			got, err := e.Decide(context.Background(), policy.Context{}, policy.ToolCall{Name: "WebFetch", Input: []byte(tc.in)})
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.want || got.Rule != tc.rule {
				t.Errorf("got %s/%s (%s), want %s/%s", got.Verdict, got.Rule, got.Reason, tc.want, tc.rule)
			}
		})
	}
}

// Finding 1 and 2: an allowed host must not hide the real host, and special
// schemes without "//" must still yield a host. github.com is allowlisted.
func TestHostSmuggling(t *testing.T) {
	cases := []struct {
		name    string
		tool    string
		key     string
		in      string
		want    policy.Verdict // when wantErr is false
		wantErr bool           // the walker rejects the input (the guard turns that into BLOCK)
	}{
		{name: "quote ends match", in: "http://github.com'@evil.example/", want: policy.Block},
		{name: "paren", in: "http://github.com)@evil.example/", want: policy.Block},
		{name: "lt", in: "http://github.com<@evil.example/", want: policy.Block},
		{name: "dquote", in: `http://github.com"@evil.example/`, want: policy.Block},
		{name: "tab", in: "http://github.com\t@evil.example/", want: policy.Block},
		{name: "newline", in: "http://github.com\n@evil.example/", want: policy.Block},
		{name: "cr", in: "http://github.com\r@evil.example/", want: policy.Block},
		{name: "backslash", in: `http://github.com\@evil.example/`, want: policy.Block},
		{name: "bash quoted", tool: "Bash", key: "command", in: `curl 'http://github.com'"'"'@evil.example/'`, want: policy.Block},
		{name: "one slash", in: "http:/evil.example/x", want: policy.Block},
		{name: "no slash", in: "http:evil.example/x", want: policy.Block},
		{name: "backslashes", in: `http:\\evil.example\x`, want: policy.Block},
		{name: "node fetch", tool: "Bash", key: "command", in: `node -e "fetch('http:/evil.example/')"`, want: policy.Block},
		{name: "ws one slash", in: "ws:/evil.example/", want: policy.Block},
		{name: "empty host", in: "http:///", wantErr: true},
		{name: "invalid host chars", in: "http://git%hub.com/", wantErr: true},
		{name: "percent in host", in: "http://evil.example%2f.github.com/", wantErr: true},

		{name: "plain", in: "https://github.com/x", want: policy.Allow},
		{name: "userinfo", in: "https://user@github.com/x", want: policy.Allow},
		{name: "at after path", in: "http://github.com/@evil.example", want: policy.Allow},
		{name: "at in query", in: "https://github.com:443/x?a=b@evil.example", want: policy.Allow},
		{name: "extra slashes then host", in: "http:///github.com/x", want: policy.Allow},
		{name: "one slash allowed host", in: "http:/github.com/x", want: policy.Allow},
		{name: "quoted url", tool: "Bash", key: "command", in: `curl "https://github.com"`, want: policy.Allow},
		{name: "prose scheme", in: "wss: ok", want: policy.Allow},
	}
	e := newEngine(t, baseCfg)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, key := tc.tool, tc.key
			if tool == "" {
				tool, key = "WebFetch", "url"
			}
			got, err := e.Decide(context.Background(), policy.Context{}, policy.ToolCall{Name: tool, Input: []byte(obj(key, tc.in))})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want an error, got %s/%s", got.Verdict, got.Rule)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Verdict != tc.want {
				t.Errorf("got %s/%s (%s), want %s", got.Verdict, got.Rule, got.Reason, tc.want)
			}
		})
	}
}

// Finding 7: a candidate that is not a valid host name or address never matches a
// wildcard entry, whatever path produced it.
func TestInvalidHostNeverMatchesWildcard(t *testing.T) {
	e := newEngine(t, baseCfg) // allows *.pypi.org and github.com
	for _, h := range []string{"evil.example%2f.pypi.org", "evil.example!.pypi.org", "a b.pypi.org", ".pypi.org", "..pypi.org", "-x.pypi.org", "evil.example%2fgithub.com"} {
		if e.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = true", h)
		}
	}
	for _, h := range []string{"files.pypi.org", "github.com", "a.b.pypi.org"} {
		if !e.hostAllowed(h) {
			t.Errorf("hostAllowed(%q) = false", h)
		}
	}
	// Through the engine, the URL form is refused outright.
	_, err := e.Decide(context.Background(), policy.Context{}, policy.ToolCall{Name: "WebFetch", Input: []byte(obj("url", "http://evil.example%2f.pypi.org/"))})
	if err == nil {
		t.Error("URL with a percent-encoded slash in the host was not refused")
	}
}

// Finding 8: only decimal, 0x hex and leading-0 octal are IPv4 number spellings.
// 0b, 0o and underscores are not, so they must not collapse to 127.0.0.1.
func TestLooseIPv4Spellings(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"127.0.0.1", "127.0.0.1", true},
		{"2130706433", "127.0.0.1", true},
		{"0x7f000001", "127.0.0.1", true},
		{"0X7F.0.0.1", "127.0.0.1", true},
		{"0177.0.0.1", "127.0.0.1", true},
		{"0x7f.0.1", "127.0.0.1", true},
		{"169.254.43518", "169.254.169.254", true},
		{"0", "0.0.0.0", true},
		{"0b1111111.0.0.1", "", false},
		{"0B1111111.0.0.1", "", false},
		{"0o177.0.0.1", "", false},
		{"1_27.0.0.1", "", false},
		{"127.0.0.0_1", "", false},
		{"0x", "", false},
		{"0x.0.0.1", "", false},
		{"08.0.0.1", "", false},
		{"+127.0.0.1", "", false},
		{"-1.0.0.1", "", false},
		{"256.0.0.1", "", false},
		{"1.2.3.4.5", "", false},
		{"4294967296", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := looseIPv4(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("looseIPv4(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
	e := newEngine(t, "tools: [WebFetch]\nhosts: [127.0.0.1]\npaths:\n  allow: [\"/work\"]\n")
	for _, u := range []string{"http://0b1111111.0.0.1/", "http://0o177.0.0.1/", "http://1_27.0.0.1/"} {
		got, err := e.Decide(context.Background(), policy.Context{}, policy.ToolCall{Name: "WebFetch", Input: []byte(obj("url", u))})
		if err == nil && got.Verdict == policy.Allow {
			t.Errorf("%s was allowed as 127.0.0.1", u)
		}
	}
}
