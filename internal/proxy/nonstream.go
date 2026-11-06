package proxy

import (
	"context"
	"encoding/json"
	"errors"

	"agent-guard/internal/policy"
)

// rewriteMessage inspects a non-streaming Messages response and replaces every tool_use block
// that is not ALLOWed with a text block. Any parse problem is an error (fail closed).
func (p *Proxy) rewriteMessage(ctx context.Context, pc policy.Context, raw []byte) ([]byte, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, err
	}
	contentRaw, ok := top["content"]
	if !ok {
		return nil, errors.New("response has no content")
	}
	var blocks []json.RawMessage
	if err := json.Unmarshal(contentRaw, &blocks); err != nil {
		return nil, err
	}

	calls, survived, replaced := 0, 0, 0
	for i, b := range blocks {
		var head struct {
			Type  string          `json:"type"`
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		}
		if err := json.Unmarshal(b, &head); err != nil {
			return nil, err
		}
		if head.Type != "tool_use" {
			continue
		}
		calls++
		var dec policy.Decision
		if calls > p.cfg.MaxToolCalls {
			dec = failClosed("fail-closed:too-many-calls", "tool call limit exceeded")
		} else {
			input := head.Input
			if len(input) == 0 {
				input = json.RawMessage("{}")
			}
			dec = p.guard.decide(ctx, pc, policy.ToolCall{ID: head.ID, Name: head.Name, Input: input})
		}
		if dec.Verdict == policy.Allow {
			survived++
			continue
		}
		replaced++
		repl, err := json.Marshal(map[string]string{"type": "text", "text": notice(dec)})
		if err != nil {
			return nil, err
		}
		blocks[i] = repl
	}
	if replaced == 0 {
		return raw, nil
	}
	newContent, err := json.Marshal(blocks)
	if err != nil {
		return nil, err
	}
	top["content"] = newContent
	var stop string
	_ = json.Unmarshal(top["stop_reason"], &stop)
	if survived == 0 && stop == "tool_use" {
		top["stop_reason"] = json.RawMessage(`"end_turn"`)
	}
	return json.Marshal(top)
}
