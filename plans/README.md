# Plans

These are the step-by-step plans written while building agent-guard, each reviewed before the code
was written. They are a **record of how decisions were made**, not documentation of the current
behaviour. Where a plan and the code or the README disagree, the code and the README win. (For
example, `step-2.md` describes a first binary that denied every tool call; the real policy engine
arrived in step 3.)

| File | Covers |
|------|--------|
| `step-2.md` | The proxy skeleton |
| `step-2b.md` | Fixes from the first code review |
| `step-2c.md` | Resource hardening (limits, deadlines, connection cap) and review fixes |
| `step-3.md` | The rules engine, including the known limits of the host heuristics |
| `step-4.md` | The audit log and OpenTelemetry |

The requirements and the decisions behind them are in [`../REQUIREMENTS.md`](../REQUIREMENTS.md).
