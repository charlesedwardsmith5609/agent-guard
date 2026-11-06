package rules

import (
	"context"
	"strings"

	"agent-guard/internal/policy"
)

// Rule names reported in decisions.
const (
	RuleToolNotDeclared = "tool-not-declared"
	RuleHostNotAllowed  = "host-not-allowed"
	RulePathOutOfScope  = "path-out-of-scope"
	RuleAllow           = "allow"
	rulePrefixSensitive = "sensitive:"
)

type finding struct {
	verdict policy.Verdict
	rule    string
	reason  string
}

func rank(v policy.Verdict) int {
	switch v {
	case policy.Block:
		return 2
	case policy.Ask:
		return 1
	}
	return 0
}

// Decide evaluates every rule and returns the strictest verdict; among equal verdicts the first
// rule in evaluation order (tool, sensitive, host, scope) is reported. An unparseable input is
// an error, which the proxy's guard turns into BLOCK.
func (e *Engine) Decide(ctx context.Context, pc policy.Context, tc policy.ToolCall) (policy.Decision, error) {
	if err := ctx.Err(); err != nil {
		return policy.Decision{}, err
	}
	ex, err := extract(ctx, tc.Input)
	if err != nil {
		return policy.Decision{}, err
	}
	var fs []finding

	if !e.toolDeclared(tc.Name) {
		fs = append(fs, finding{policy.Block, RuleToolNotDeclared, "tool " + quote(tc.Name) + " is not declared"})
	}
	if err := ctx.Err(); err != nil {
		return policy.Decision{}, err
	}
	for _, p := range ex.candidates {
		if c := e.pathClass(p); c != "" {
			fs = append(fs, finding{e.sensitive[c], rulePrefixSensitive + c, "sensitive path " + quote(p)})
		}
	}
	for _, h := range ex.hosts {
		if c := hostClass(h); c != "" {
			fs = append(fs, finding{e.sensitive[c], rulePrefixSensitive + c, "sensitive host " + quote(h)})
		}
	}
	if err := ctx.Err(); err != nil {
		return policy.Decision{}, err
	}
	var unlisted []string
	for _, h := range ex.hosts {
		if !e.hostAllowed(h) {
			unlisted = append(unlisted, h)
		}
	}
	if len(unlisted) > 0 {
		said, err := mentionedHosts(ctx, unlisted, pc.UserText)
		if err != nil {
			return policy.Decision{}, err
		}
		for _, h := range unlisted {
			if !said[h] {
				fs = append(fs, finding{policy.Block, RuleHostNotAllowed, "host " + quote(h) + " is not allowlisted or mentioned by the user"})
			}
		}
	}
	for _, p := range ex.structured {
		if !e.inScope(p) {
			fs = append(fs, finding{policy.Block, RulePathOutOfScope, "path " + quote(p) + " is outside the allowed scopes"})
		}
	}

	best := finding{policy.Allow, RuleAllow, "no rule matched"}
	for _, f := range fs {
		if rank(f.verdict) > rank(best.verdict) {
			best = f
		}
	}
	return policy.Decision{Verdict: best.verdict, Rule: best.rule, Reason: best.reason}, nil
}

func quote(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteByte('?')
		} else {
			b.WriteRune(r)
		}
	}
	return `"` + b.String() + `"`
}

func (e *Engine) toolDeclared(name string) bool {
	if e.toolsExact[name] {
		return true
	}
	for _, p := range e.toolsPrefix {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func (e *Engine) hostAllowed(h string) bool {
	if e.hostsExact[h] {
		return true
	}
	for _, suf := range e.hostSuffix {
		if strings.HasSuffix(h, suf) { // suf starts with ".", so the apex never matches
			return true
		}
	}
	return false
}

// inScope reports whether a structured path lies inside an allowed prefix. Relative paths
// resolve against workdir; `..` is resolved lexically.
func (e *Engine) inScope(p string) bool {
	p = e.expandHome(p)
	if !strings.HasPrefix(p, "/") {
		p = e.workdir + "/" + p
	}
	p = cleanAbs(p)
	for _, a := range e.allow {
		if a == "/" || p == a || strings.HasPrefix(p, a+"/") {
			return true
		}
	}
	return false
}

// mentioned reports whether host appears as a whole token (case-insensitive) in the user text.
func mentioned(host string, texts []string) bool {
	m, _ := mentionedHosts(context.Background(), []string{host}, texts)
	return m[strings.ToLower(host)]
}

// mentionedHosts scans the user text once and reports which of the wanted hosts appear as whole
// tokens. A token is a maximal run of [a-z0-9._-]; surrounding dots (a sentence's full stop) are
// trimmed, so "evil.com." matches evil.com but "evil.com.attacker.net" does not.
func mentionedHosts(ctx context.Context, wanted []string, texts []string) (map[string]bool, error) {
	want := make(map[string]bool, len(wanted))
	for _, h := range wanted {
		want[strings.ToLower(h)] = true
	}
	found := map[string]bool{}
	for _, t := range texts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		t = strings.ToLower(t)
		start := -1
		for i := 0; i <= len(t); i++ {
			if i&0xffff == 0 && ctx.Err() != nil { // every 64 KiB
				return nil, ctx.Err()
			}
			if i < len(t) && (isHostChar(t[i]) || t[i] == '.') {
				if start < 0 {
					start = i
				}
				continue
			}
			if start >= 0 {
				if w := strings.Trim(t[start:i], "."); want[w] {
					found[w] = true
				}
				start = -1
			}
		}
	}
	return found, nil
}

func isHostChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}
