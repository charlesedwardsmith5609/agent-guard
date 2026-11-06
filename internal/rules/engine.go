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
	for _, h := range ex.hosts {
		if !e.hostAllowed(h) && !mentioned(h, pc.UserText) {
			fs = append(fs, finding{policy.Block, RuleHostNotAllowed, "host " + quote(h) + " is not allowlisted or mentioned by the user"})
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
	host = strings.ToLower(host)
	for _, t := range texts {
		t = strings.ToLower(t)
		for from := 0; ; {
			i := strings.Index(t[from:], host)
			if i < 0 {
				break
			}
			start, end := from+i, from+i+len(host)
			if boundaryBefore(t, start) && boundaryAfter(t, end) {
				return true
			}
			from = start + 1
		}
	}
	return false
}

func isHostChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}

func boundaryBefore(t string, i int) bool {
	if i == 0 {
		return true
	}
	return !isHostChar(t[i-1]) && t[i-1] != '.'
}

func boundaryAfter(t string, i int) bool {
	if i >= len(t) {
		return true
	}
	if isHostChar(t[i]) {
		return false
	}
	// A dot continues the name unless it ends a sentence.
	return !(t[i] == '.' && i+1 < len(t) && isHostChar(t[i+1]))
}
