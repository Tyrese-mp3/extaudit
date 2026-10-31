"""Find risky combinations across extensions installed together.

A prompt injection needs two halves: something that brings attacker-written text
into the conversation, and something able to act on it. Each half can look fine
alone, so scanning one extension at a time misses the risk. These are possible
paths, not confirmed exploits: each one depends on Claude following the text.
"""

from __future__ import annotations

from .model import (
    AGENT_CONFIG,
    EXEC,
    FS_READ,
    FS_WRITE,
    MODEL_REACHABLE,
    NET,
    PERSIST,
    REACH_DECLARED,
    REACH_INFERRED,
    REACH_TOOL,
    SECRETS,
    UNTRUSTED,
    Extension,
    Finding,
    Severity,
)
from .patterns import clip

SET_NAME = "(installed together)"
INJECTION_RULES = {"input.command-injection", "input.code-injection"}


def find_chains(extensions: list[Extension]) -> list[Finding]:
    chains: list[Finding] = []
    sources = [e for e in extensions if e.has(UNTRUSTED)]
    approved = _auto_approved(extensions)
    if sources:
        chains.extend(_injection_to_exec(sources, extensions, approved))
        chains.extend(_data_theft(sources, extensions, approved))
        chains.extend(_injection_to_config(sources, extensions, approved))
    chains.extend(_tool_shadowing(extensions))
    return sorted(chains, key=lambda c: -c.severity)


def _names(extensions: list[Extension]) -> str:
    return ", ".join(sorted(clip(e.name, 40) for e in extensions))


def _chain(rule, severity, title, detail, fix) -> Finding:
    return Finding(rule, "chain", severity, title, detail, fix=fix, extension=SET_NAME)


def _auto_approved(extensions: list[Extension]) -> set[str]:
    """Names of MCP servers whose tools run without a prompt in Claude Code."""
    names: set[str] = set()
    for extension in extensions:
        permissions = extension.settings.get("permissions")
        allow = permissions.get("allow") if isinstance(permissions, dict) else None
        for rule in allow if isinstance(allow, list) else []:
            text = str(rule)
            if text.startswith("mcp__"):
                parts = text.split("__")
                if len(parts) > 1:
                    names.add(parts[1].lower())
    return names


def _is_approved(extension: Extension, approved: set[str]) -> bool:
    names = {extension.name.lower(), *(s.name.lower() for s in extension.servers)}
    return bool(names & approved)


def _raise_if_approved(severity: Severity, targets: list[Extension], approved: set[str]) -> tuple[Severity, str]:
    listed = [e for e in targets if _is_approved(e, approved)]
    if not listed:
        return severity, ""
    return severity.raised(), (
        f" No prompt would stop this: tools from {_names(listed)} are auto-approved."
    )


def _injection_to_exec(sources, extensions, approved) -> list[Finding]:
    results: list[Finding] = []
    source_names = _names(sources)
    injectable = [e for e in extensions if any(f.rule in INJECTION_RULES for f in e.findings)]
    direct = [e for e in extensions if e.has(EXEC, {REACH_TOOL, REACH_DECLARED}) and e not in injectable]
    guessed = [
        e for e in extensions
        if e.has(EXEC, {REACH_INFERRED}) and e not in injectable and e not in direct
    ]
    for targets, base, how in (
        (injectable, Severity.CRITICAL, "passes tool input into a command or code"),
        (direct, Severity.HIGH, "gives Claude a tool that runs commands"),
        (guessed, Severity.MEDIUM, "looks like it runs commands, judging by its name"),
    ):
        for target in targets:
            severity, note = _raise_if_approved(base, [target], approved)
            results.append(_chain(
                "chain.injection-to-exec", severity,
                f"Outside content could lead to commands through {clip(target.name, 40)}",
                f"{source_names} can bring text written by other people into the conversation. "
                f"{clip(target.name, 40)} {how}. Hidden instructions in that text could ask "
                f"Claude to use it.{note}",
                f"Disable one side, or keep confirmation prompts on for {clip(target.name, 40)}.",
            ))
    return results


def _data_theft(sources, extensions, approved) -> list[Finding]:
    reachable = MODEL_REACHABLE
    readers = [e for e in extensions if e.has(FS_READ, reachable) or e.has(SECRETS, reachable)]
    senders = [e for e in extensions if e.has(NET, reachable)]
    if not readers or not senders:
        return []
    weak = not any(e.has(FS_READ, {REACH_TOOL}) or e.has(SECRETS, {REACH_TOOL}) for e in readers)
    severity = Severity.MEDIUM if weak else Severity.HIGH
    severity, note = _raise_if_approved(severity, [*readers, *senders], approved)
    return [_chain(
        "chain.data-theft", severity,
        "Outside content, private files and a way out are all present",
        f"Text from {_names(sources)} could ask Claude to read local data with "
        f"{_names(readers)}, then send it out through {_names(senders)}.{note}",
        "Remove one of the three roles, or review each tool call before it runs.",
    )]


def _injection_to_config(sources, extensions, approved) -> list[Finding]:
    writers = [
        e for e in extensions
        if e.has(FS_WRITE, {REACH_TOOL, REACH_DECLARED})
        or e.has(AGENT_CONFIG, {REACH_TOOL, REACH_DECLARED})
        or e.has(PERSIST, {REACH_TOOL, REACH_DECLARED})
    ]
    if not writers:
        return []
    severity, note = _raise_if_approved(Severity.HIGH, writers, approved)
    return [_chain(
        "chain.injection-to-persistence", severity,
        "Outside content could lead to lasting changes on this machine",
        f"Text from {_names(sources)} could ask Claude to write files with {_names(writers)}. "
        f"A write to CLAUDE.md, a hook or a shell profile would outlive the session.{note}",
        "Limit file tools to a project folder and review writes outside it.",
    )]


def _tool_shadowing(extensions) -> list[Finding]:
    owners: dict[str, set[str]] = {}
    for extension in extensions:
        for tool in extension.tools:
            if tool.name:
                owners.setdefault(tool.name, set()).add(extension.name)
    results = []
    for name, names in sorted(owners.items()):
        if len(names) > 1:
            results.append(_chain(
                "chain.tool-name-collision", Severity.MEDIUM,
                f"Tool '{clip(name, 40)}' exists in {len(names)} extensions",
                f"Offered by {', '.join(sorted(clip(n, 40) for n in names))}. "
                "Claude might call a different one than you expect.",
                "Disable one of them, or rename the tool.",
            ))
    return results
