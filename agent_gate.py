#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent_gate — a pre-execution gate for AI agent tool calls.

Two layers, checked in order, before the tool ever runs:

  1. HARD BLOCK — deterministic regex rules. Clearly dangerous calls
     (format, diskpart, rm -rf /, credential-store access, HKLM writes,
     remote exec...) never reach an LLM; code refuses them outright.
  2. SOFT JUDGE — ambiguous side-effect calls are judged by a small LLM
     (Ollama by default; any OpenAI-compatible endpoint works).
     If the judge is unavailable: command tools fall back to a safe
     whitelist (fail-closed), file tools pass (content already scanned).

Wire it before your executor:

    from agent_gate import check
    allow, reason = check("run_command", {"command": "rm -rf /"})
    if not allow:
        raise PermissionError(reason)

Config — drop .agentgate.json next to your project (optional):
    {
      "block_cmd":   [["regex", "reason"], ...],       # appended hard rules
      "block_path":  [["regex", "reason"], ...],
      "protected_files": [["\\\\.pcap$", "never overwrite pcaps"]],
      "safe_cmd_prefixes": ["echo", "git status", ...], # replace whitelist
      "judge_tools": ["run_command", "write_file"],
      "judge_backend": "ollama" | "openai" | "none",
      "judge_model": "qwen2.5-coder:7b"
    }

Env: AGENT_GATE=0 disables · AGENT_GATE_LLM=0 rules-only
     OLLAMA_URL / OPENAI_BASE_URL / OPENAI_API_KEY / GATE_MODEL

Zero dependencies — Python 3.10+ standard library only.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from pathlib import Path

_logger = logging.getLogger("agent_gate")

# ── config ────────────────────────────────────────────
ENABLED = os.environ.get("AGENT_GATE", "1") != "0"
LLM_JUDGE_ENABLED = os.environ.get("AGENT_GATE_LLM", "1") != "0"
JUDGE_TIMEOUT = int(os.environ.get("AGENT_GATE_TIMEOUT", "25"))
_OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")


def _load_config() -> dict:
    """Search cwd and its parents for .agentgate.json."""
    for d in [Path.cwd(), *Path.cwd().parents]:
        p = d / ".agentgate.json"
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                _logger.warning(f"bad .agentgate.json ignored: {p}")
    return {}


_CFG = _load_config()

# ── layer 1: hard-block rules ─────────────────────────
# Deterministic — no model judgement, no mercy.

_CMD_BLOCK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # disk / boot destruction
    (re.compile(r"\bformat(\.exe)?\s+[a-zA-Z]:", re.I), "disk format"),
    (re.compile(r"\bdiskpart\b", re.I), "disk partitioning (diskpart)"),
    (re.compile(r"\bbcdedit\b", re.I), "boot config edit (bcdedit)"),
    (re.compile(r"\bvssadmin\b[^;&|]*delete\s+shadows", re.I), "shadow copy delete"),
    (re.compile(r"\bwbadmin\b[^;&|]*delete", re.I), "backup delete (wbadmin)"),
    (re.compile(r"\bcipher\b[^;&|]*/w", re.I), "disk wipe (cipher /w)"),

    # shutdown / reboot
    (re.compile(r"\bshutdown(\.exe)?\s+/[sr]", re.I), "shutdown/reboot command"),
    (re.compile(r"\bRestart-Computer\b", re.I), "reboot (Restart-Computer)"),
    (re.compile(r"\bStop-Computer\b", re.I), "shutdown (Stop-Computer)"),

    # broad deletes — only when aimed at system roots; user subfolder
    # cleanup is normal work and must pass
    (re.compile(
        r"(\brd\b|\brmdir\b|\bdel\b|\berase\b|\brm\b|\bRemove-Item\b)[^;&|\n]*"
        r"(C:\\(?=[\s\"';&|)]|$)|C:\\Windows|C:\\Program Files|C:\\ProgramData|"
        r"C:\\Users(?=[\s\"';&|)]|$)|"
        r"%SystemRoot%|%USERPROFILE%(?=[\s\"';&|)]|$))",
        re.I), "delete aimed at system/user root"),
    (re.compile(r"\brm\s+-[rf]+\s+[/~]", re.I), "recursive delete of / or ~"),
    (re.compile(r"\bRemove-Item\b[^;&|\n]*-Recurse[^;&|\n]*"
                r"(C:\\Windows|C:\\Users\b|%SystemRoot%)", re.I),
     "recursive delete of system path (PS)"),

    # system config changes
    (re.compile(r"\bsc(\.exe)?\s+(stop|delete|config)\b", re.I), "service stop/delete/config"),
    (re.compile(r"\bnet\s+(user|localgroup)\b[^;&|\n]*(/add|/delete|\*)", re.I),
     "user account add/delete"),
    (re.compile(r"\breg(\.exe)?\s+(delete|add)\s+HKLM", re.I), "HKLM registry write"),
    (re.compile(r"\bpnputil\b[^;&|\n]*delete-driver", re.I), "driver removal"),
    (re.compile(r"netsh\s+advfirewall\s+set[^;&|\n]*off", re.I), "firewall off"),
    (re.compile(r"Set-NetFirewallProfile[^;&|\n]*-Enabled\s+(False|\$false|0)", re.I),
     "firewall off (PS)"),
    (re.compile(r"Set-MpPreference[^;&|\n]*Disable", re.I), "Defender realtime off"),

    # credential / secret stores
    (re.compile(r"(Login Data|Cookies|Web Data|Local State|"
                r"Network\\Cookies|\.ssh[\\/]|id_rsa|id_ed25519)", re.I),
     "browser credential / SSH key store"),
    (re.compile(r"(\.env\b|wallet\.dat|\.aws[\\/]credentials)", re.I),
     "secret/wallet/credential file"),

    # remote execution
    (re.compile(r"\bpsexec\b", re.I), "remote exec (psexec)"),
    (re.compile(r"\bwmic\b[^;&|\n]*/node:", re.I), "remote exec (wmic)"),
    (re.compile(r"Invoke-Command[^;&|\n]*-ComputerName", re.I), "remote exec (PS)"),
] + [(re.compile(rx, re.I), why)
     for rx, why in _CFG.get("block_cmd", [])]

_PATH_BLOCK_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^[a-zA-Z]:[\\/]Windows", re.I), "write to Windows dir"),
    (re.compile(r"^[a-zA-Z]:[\\/]Program Files", re.I), "write to Program Files"),
    (re.compile(r"(Login Data|Cookies|Web Data|Local State|"
                r"\.ssh[\\/]|id_rsa|id_ed25519|wallet\.dat)", re.I),
     "write to credential/key file"),
] + [(re.compile(rx, re.I), why)
     for rx, why in _CFG.get("block_path", [])]

# project-specific "never touch these existing files" rules, e.g. pcap originals
_PROTECTED_FILES = [(re.compile(rx, re.I), why)
                    for rx, why in _CFG.get("protected_files", [])]


def _hardblock_cmd(cmd: str) -> str | None:
    for pat, reason in _CMD_BLOCK_PATTERNS:
        if pat.search(cmd):
            return reason
    return None


def _hardblock_path(path: str) -> str | None:
    if not path:
        return None
    p = path.replace("/", "\\").strip().strip('"')
    for pat, reason in _PATH_BLOCK_PATTERNS:
        if pat.search(p):
            return reason
    for pat, reason in _PROTECTED_FILES:
        if pat.search(p) and os.path.isfile(p):
            return reason
    return None


# ── layer 2: small-model soft judge ───────────────────

_JUDGE_PROMPT = """You are a strict supervisor judging whether an AI agent's action is safe.
Judge ONLY the proposed tool call below — nothing else.

Tool call to judge:
Tool: {tool}
Arguments:
{args}

Rules:
- DENY if it could damage the system, destroy data, change security settings,
  access credentials/secrets, or run remotely on other machines.
- DENY if the action is unrelated to normal software development work.
- ALLOW normal development actions: running scripts, building, editing project
  files, reading system info, package installs, git operations.

Reply with ONLY a JSON object: {{"verdict": "allow" or "deny", "reason": "short reason"}}"""


# fail-closed whitelist when the judge cannot answer
_SAFE_CMD_PREFIXES = tuple(_CFG.get("safe_cmd_prefixes", [
    "dir", "ls", "type", "cat", "echo", "cd", "pwd", "where", "which",
    "python", "py ", "pip", "pytest", "node", "npm", "npx",
    "git status", "git log", "git diff", "git show", "git add",
    "git commit", "git branch", "git checkout", "git switch",
    "git stash", "git pull", "git fetch", "git push",
    "ollama", "ipconfig", "systeminfo", "tasklist", "winget list",
    "chcp", "ver", "set ", "findstr", "find ", "rg ", "tree",
]))


def _obviously_safe_cmd(cmd: str) -> bool:
    """Every piped/chained stage must start with a whitelisted prefix."""
    c = (cmd or "").strip().lower()
    if not c:
        return False
    for part in re.split(r"[;&|]+", c):
        part = part.strip()
        if part and not any(part.startswith(p) for p in _SAFE_CMD_PREFIXES):
            return False
    return True


def _judge_backend() -> str:
    return _CFG.get("judge_backend") or (
        "openai" if os.environ.get("OPENAI_BASE_URL") else "ollama")


def _judge_model() -> str:
    return (_CFG.get("judge_model") or os.environ.get("GATE_MODEL")
            or "qwen2.5-coder:7b")


def _call_ollama(prompt: str) -> str:
    payload = json.dumps({
        "model": _judge_model(), "prompt": prompt, "stream": False,
        "options": {"temperature": 0.0, "num_ctx": 4096, "num_predict": 200},
    }).encode("utf-8")
    req = urllib.request.Request(f"{_OLLAMA_URL}/api/generate", data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=JUDGE_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8")).get("response", "")


def _call_openai(prompt: str) -> str:
    base = os.environ["OPENAI_BASE_URL"].rstrip("/")
    key = os.environ.get("OPENAI_API_KEY", "")
    payload = json.dumps({
        "model": _judge_model(), "temperature": 0.0, "max_tokens": 200,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(f"{base}/chat/completions", data=payload,
                                 headers={"Content-Type": "application/json",
                                          "Authorization": f"Bearer {key}"})
    with urllib.request.urlopen(req, timeout=JUDGE_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))["choices"][0]["message"]["content"]


def _judge_once(tool: str, args: dict) -> tuple[bool | None, str]:
    """One judgement → (allow/deny/None=undecidable, reason)."""
    try:
        backend = _judge_backend()
        if backend == "none":
            return None, "judge disabled"
        args_str = json.dumps(args, ensure_ascii=False)
        if len(args_str) > 2000:
            args_str = args_str[:2000] + "...(truncated)"
        prompt = _JUDGE_PROMPT.format(tool=tool, args=args_str)
        text = (_call_openai(prompt) if backend == "openai"
                else _call_ollama(prompt)).strip()
        text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None, f"no JSON in reply ({text[:80]!r})"
        verdict = json.loads(m.group(0))
        if str(verdict.get("verdict", "")).lower() == "deny":
            return False, str(verdict.get("reason", "denied by judge"))
        return True, ""
    except Exception as e:
        return None, str(e)


def _judge(tool: str, args: dict) -> tuple[bool, str]:
    """Soft judgement with one retry. If the judge can't answer:
    - command tools: whitelist only (fail-closed)
    - other tools: allow — path+content already passed hard-block scan
    """
    if not LLM_JUDGE_ENABLED:
        return True, ""
    verdict, info = _judge_once(tool, args)
    if verdict is None:
        _logger.warning(f"agent_gate judge failed once — retrying: {info}")
        verdict, info = _judge_once(tool, args)
    if verdict is not None:
        return verdict, info
    _logger.warning(f"agent_gate judge undecidable ({tool}): {info}")
    if tool in ("run_command", "run_python"):
        cmd = str(args.get("cmd") or args.get("command") or
                  args.get("code") or args.get("script") or "")
        if _obviously_safe_cmd(cmd):
            return True, ""
        return False, ("judge unavailable — non-whitelisted commands are "
                       "denied until the judge recovers")
    return True, ""


# ── public API ────────────────────────────────────────

# tools whose side effects need a judge opinion
_JUDGE_TOOLS = set(_CFG.get("judge_tools", [
    "run_command", "run_python", "write_file", "apply_patch",
    "git_commit", "image_edit", "generate_image",
]))


def check(tool: str, args: dict) -> tuple[bool, str]:
    """Gate a tool call before execution.
    Returns (allowed, deny_reason). Empty reason when allowed."""
    if not ENABLED:
        return True, ""
    args = args or {}

    try:
        # layer 1 — hard block
        if tool in ("run_command", "run_python"):
            cmd = str(args.get("cmd") or args.get("command") or
                      args.get("code") or args.get("script") or "")
            reason = _hardblock_cmd(cmd)
            if reason:
                return False, f"[hardblock] {reason}"
        elif tool in ("write_file", "apply_patch"):
            path = str(args.get("path") or args.get("file") or "")
            reason = _hardblock_path(path)
            if reason:
                return False, f"[hardblock] {reason}"
            # scan file content too — blocks writing malicious scripts
            content = str(args.get("content") or args.get("patch") or "")
            if len(content) < 50000:
                reason = _hardblock_cmd(content)
                if reason:
                    return False, f"[hardblock] dangerous command in file body: {reason}"

        # layer 2 — soft judge
        if tool in _JUDGE_TOOLS:
            allow, reason = _judge(tool, args)
            if not allow:
                return False, f"[judge] {reason}"
        return True, ""
    except Exception as e:
        _logger.warning(f"agent_gate check error — fail-open: {e}")
        return True, ""
