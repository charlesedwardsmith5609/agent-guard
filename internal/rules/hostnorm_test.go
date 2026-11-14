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
