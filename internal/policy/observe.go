package policy

import (
	"context"
	"strings"
	"time"
)

// Event describes one finished decision, as seen by the proxy.
type Event struct {
	Call       ToolCall
	Decision   Decision
	Start, End time.Time
	Stream     bool
	// Agent is the raw agent identity from the request, if any. The audit log
	// redacts it before writing.
	Agent string
	// Kind is "" for an ordinary decision, or "refusal" when the halt switch
	// refused the call before the policy ran.
	Kind string
}

// Observer receives every decision. Implementations must not block: they are called on the
// request path. A non-nil error means the event could not be recorded.
type Observer interface {
	Observe(ctx context.Context, e Event) error
}

// SafeID reduces an untrusted identifier (tool name, tool_use id) to [A-Za-z0-9_.:/-], at most
// 128 bytes, so it is safe to record and to use as a span attribute.
func SafeID(s string) string {
	const max = 128
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '.', c == ':', c == '/', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}
