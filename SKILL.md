---
name: agent-gate
description: Pre-execution gate for AI agent tool calls — hard-block dangerous commands deterministically, LLM-judge ambiguous ones, fail-closed whitelist when the judge is down. Use when building or hardening a coding agent that can run commands/write files.
allowed-tools:
  - read
  - exec
---

# agent-gate — tool-call firewall

`agent_gate.check(tool, args)` returns `(allowed, reason)` **before** a tool
executes. Drop it between any agent loop and its executor:

```python
from agent_gate import check
allow, reason = check("run_command", {"command": cmd})
if not allow:
    return f"blocked: {reason}"
```

Layers: deterministic hard-block (destructive/system/credential/remote patterns)
→ optional LLM judge for ambiguous calls → fail-closed whitelist fallback when
the judge is unreachable. Rules-only mode works with zero LLM
(`AGENT_GATE_LLM=0`).

Project-specific rules go in `.agentgate.json` (extra regex blocks, protected
files, judge model) — see `.agentgate.example.json`. Test with `python demo.py`
(deterministic, no LLM) or `python demo.py --judge` (needs Ollama).
