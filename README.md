# agent-gate

A pre-execution gate for AI agent tool calls — one file, zero dependencies.

Coding agents can run commands and write files. The permission models bundled
into agent frameworks are mostly "ask the user" or "trust the model" — both
leak. `agent_gate.check()` sits **between the agent and the executor** and
returns `allow/deny` before anything runs.

## Two layers

```
tool call ──▶ ① HARD BLOCK — deterministic regex rules, no LLM
                 (format, diskpart, rm -rf, credential stores, HKLM,
                  firewall off, remote exec, write to system dirs...)
              ② SOFT JUDGE — a small LLM scores ambiguous side-effect calls
                 (Ollama by default, any OpenAI-compatible endpoint works)
                 judge down? → commands fall back to a whitelist (fail-closed)
```

The interesting part is the failure mode: **when the judge can't answer, only
obviously-safe commands pass** — the gate fails closed where it matters and
open where it doesn't.

## Quickstart

```python
from agent_gate import check

allow, reason = check("run_command", {"command": "rm -rf /"})
if not allow:
    raise PermissionError(reason)     # your executor never sees the call
```

```bash
python demo.py            # deterministic rules-only demo, no LLM needed
python demo.py --judge    # soft layer too (needs Ollama running)
```

## Configuration

Optional `.agentgate.json` in your project root — extra block rules, protected
files, judge model/backend, safe whitelist. See `.agentgate.example.json`.

| Key | Meaning |
|---|---|
| `block_cmd` | `[[regex, reason], …]` extra hard-block patterns for shell calls |
| `block_path` | same for file-write targets |
| `protected_files` | `[[regex, reason], …]` existing files that may never be overwritten |
| `safe_cmd_prefixes` | replace the fail-closed whitelist |
| `judge_tools` | which tool names get an LLM judgement |
| `judge_backend` | `ollama` (default) \| `openai` \| `none` |
| `judge_model` | judge model name |

Env: `AGENT_GATE=0` disables · `AGENT_GATE_LLM=0` rules-only ·
`OLLAMA_URL`, `OPENAI_BASE_URL`/`OPENAI_API_KEY`/`GATE_MODEL` for the judge.

Free-tier judge options that work out of the box: local Ollama, NVIDIA
build.nvidia.com, Google AI Studio — all OpenAI-compatible.

## Why not just use the framework's permission mode?

Framework permission prompts are human-approval UIs — fine interactively, useless
for headless/autonomous runs. `agent_gate` is a library: deterministic blocks +
LLM judgement + explicit degraded-mode policy, embeddable in one line.

## License

MIT — see [LICENSE](LICENSE).

---

Built by **성안컴퓨터 (SeongAn Computer)** — a neighborhood computer shop in
South Korea that writes its own tools instead of buying them.
More of our work at [sounganh.com](https://sounganh.com).
