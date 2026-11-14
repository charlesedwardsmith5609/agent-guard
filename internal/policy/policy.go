// Package policy defines the types shared between the proxy and the rules engine.
package policy

import (
	"context"
	"encoding/json"
)

// Verdict is the outcome of evaluating one tool call.
type Verdict string

const (
	Allow Verdict = "ALLOW"
	Block Verdict = "BLOCK"
	Ask   Verdict = "ASK"
)

// Valid reports whether v is one of the three known verdicts.
func (v Verdict) Valid() bool { return v == Allow || v == Block || v == Ask }

// ToolCall is one tool invocation emitted by the model.
type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// Context is what the proxy knows about the conversation that produced a tool call.
type Context struct {
	// UserText is user-role text from the whole conversation. Tool results are excluded.
	UserText []string
	// AgentID is the identity from the request, after trimming. Empty when the
	// caller did not send one.
	AgentID string
	// AgentIDRejected is set when the identity was present but not usable
	// (for example longer than the limit). It must not be treated as a known agent.
	AgentIDRejected bool
}

// Decision is a verdict plus the rule that produced it.
type Decision struct {
	Verdict Verdict
	Rule    string
	Reason  string
	// Profile is the named policy profile that produced the verdict.
	// It is empty when no profile applied.
	Profile string
}

// Decider evaluates tool calls. Implementations must be safe for concurrent use, own any state
// they keep, and honor ctx cancellation.
type Decider interface {
	Decide(ctx context.Context, c Context, t ToolCall) (Decision, error)
}

// DenyAll blocks every call. It is the fail-closed default until a rules engine exists.
type DenyAll struct{}

// Decide implements Decider.
func (DenyAll) Decide(context.Context, Context, ToolCall) (Decision, error) {
	return Decision{Verdict: Block, Rule: "deny-all", Reason: "no rules configured"}, nil
}
