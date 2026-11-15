package rules

import (
	"context"
	"sort"

	"agent-guard/internal/policy"
)

// DefaultProfile is the audit profile name when the file has no profiles map.
const DefaultProfile = "default"

// Rule names for profile selection. The call is denied before the selected
// profile's rules run.
const (
	RuleProfileMissing = "profile-missing"
	RuleProfileUnknown = "profile-unknown"
)

// Policy is the decider the proxy uses. A file with no profiles has single set
// and records DefaultProfile. A file with profiles selects by agent identity.
type Policy struct {
	single *Engine
	byName map[string]*Engine
	agents map[string]string
}

// Decide implements policy.Decider. When profiles are configured, a missing
// identity and an identity that is not in agents are denied. A malformed
// identity is treated as unknown, not as a truncated match.
func (p *Policy) Decide(ctx context.Context, c policy.Context, tc policy.ToolCall) (policy.Decision, error) {
	eng, name, denied := p.selectEngine(c)
	if denied != nil {
		return *denied, nil
	}
	d, err := eng.Decide(ctx, c, tc)
	if err != nil {
		return d, err
	}
	d.Profile = name
	return d, nil
}

// ProfileFor reports the profile name that would apply, or "" if none would.
// The halt path uses this to annotate a refusal. It does not allow the call.
func (p *Policy) ProfileFor(agentID string) string {
	c := policy.Context{AgentID: agentID}
	_, name, denied := p.selectEngine(c)
	if denied != nil {
		return ""
	}
	return name
}

func (p *Policy) selectEngine(c policy.Context) (*Engine, string, *policy.Decision) {
	if p.single != nil {
		return p.single, DefaultProfile, nil
	}
	if c.AgentIDRejected {
		d := policy.Decision{Verdict: policy.Block, Rule: RuleProfileUnknown, Reason: "agent identity is not usable"}
		return nil, "", &d
	}
	if c.AgentID == "" {
		d := policy.Decision{Verdict: policy.Block, Rule: RuleProfileMissing, Reason: "agent identity is missing"}
		return nil, "", &d
	}
	name, ok := p.agents[c.AgentID]
	eng := p.byName[name]
	if !ok || eng == nil {
		d := policy.Decision{Verdict: policy.Block, Rule: RuleProfileUnknown, Reason: "agent identity has no profile"}
		return nil, "", &d
	}
	return eng, name, nil
}

// Canaries returns every canary from every profile, for audit redaction.
func (p *Policy) Canaries() []string {
	if p.single != nil {
		return p.single.Canaries()
	}
	names := make([]string, 0, len(p.byName))
	for n := range p.byName {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		for _, c := range p.byName[n].Canaries() {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	return out
}
