"""Record what an extension can do, and report what changed between versions.

Snapshots never hold secret values: server arguments and environment values are
stored as hashes, and only the names of environment variables are kept.
"""

from __future__ import annotations

import hashlib
import json

from .model import (
    AGENT_CONFIG,
    CAPABILITY_LABELS,
    DYNAMIC,
    EXEC,
    PERSIST,
    SECRETS,
    Extension,
    Finding,
    Severity,
)
from .patterns import clip

SERIOUS_CAPABILITIES = {EXEC, DYNAMIC, SECRETS, PERSIST, AGENT_CONFIG}
FORMAT_VERSION = 1


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def build(extension: Extension) -> dict:
    return {
        "name": extension.name,
        "kind": extension.kind,
        "version": extension.version,
        "files": {f.path: hashlib.sha256(f.data).hexdigest() for f in extension.files},
        "tools": {t.name: _hash(t.description.strip()) for t in extension.tools if t.name},
        "capabilities": sorted({c.name for c in extension.capabilities}),
        "hosts": sorted(extension.hosts),
        "servers": {
            s.name: {
                "command": s.command.replace("\\", "/").rsplit("/", 1)[-1],
                "launch": _hash(json.dumps([s.command, s.args, s.url])),
                "env_names": sorted(s.env),
            }
            for s in extension.servers
        },
        "hooks": sorted({
            _hash(json.dumps([h.event, h.matcher, h.type, h.command, h.args, h.url, h.prompt]))
            + "|" + h.event
            for h in extension.hooks
        }),
        "dependencies": dict(extension.dependencies),
        "install_scripts": {k: _hash(v) for k, v in extension.install_scripts.items()},
        "instructions": {d.path: _hash(d.text) for d in extension.docs},
        "allowed_tools": {
            d.path: _hash(json.dumps(d.frontmatter.get("allowed-tools", ""), sort_keys=True))
            for d in extension.docs
        },
    }


def build_set(extensions: list[Extension]) -> dict:
    return {
        "format": FORMAT_VERSION,
        "extensions": {f"{e.kind}:{e.name}": build(e) for e in extensions},
    }


def diff(old: dict, new: dict) -> list[Finding]:
    """Compare two snapshots of the same extension."""
    name = new.get("name", "")
    out: list[Finding] = []

    def add(rule, severity, title, detail="", fix="") -> None:
        out.append(Finding(rule, "update", severity, title, detail, fix=fix, extension=name))

    version_changed = old.get("version") != new.get("version")
    if version_changed and new.get("kind") in {"npm", "pypi"}:
        add("update.package-version", Severity.MEDIUM,
            f"The launch command now fetches {clip(str(new.get('version')), 40)} (was {clip(str(old.get('version')), 40)})",
            "Nobody approved this. An unpinned server moved to a new release by itself.",
            "Pin the version you reviewed.")

    def weigh(severity: Severity) -> Severity:
        # New behavior with no new version is how a rug pull looks.
        return severity if version_changed else severity.raised()

    for capability in sorted(set(new["capabilities"]) - set(old["capabilities"])):
        label = CAPABILITY_LABELS.get(capability, capability)
        add("update.new-capability",
            weigh(Severity.HIGH if capability in SERIOUS_CAPABILITIES else Severity.MEDIUM),
            f"New ability: {label}",
            "The update can do something the previous version could not.",
            "Find out why before accepting the update.")

    old_tools, new_tools = old["tools"], new["tools"]
    for tool in sorted(set(new_tools) - set(old_tools)):
        add("update.new-tool", weigh(Severity.MEDIUM), f"New tool: {clip(tool, 60)}")
    for tool in sorted(set(old_tools) & set(new_tools)):
        if old_tools[tool] != new_tools[tool]:
            add("update.tool-description-changed",
                Severity.MEDIUM if version_changed else Severity.HIGH,
                f"Description of tool '{clip(tool, 40)}' changed"
                + ("" if version_changed else " without a version change"),
                "Claude acts on tool descriptions, so a change here can change behavior. "
                "This is how a rug pull works: approve a clean tool, then swap its text.",
                "Read the new description.")

    for host in sorted(set(new["hosts"]) - set(old["hosts"])):
        add("update.new-host", weigh(Severity.MEDIUM), f"New network destination: {clip(host, 80)}",
            "The update talks to a host the previous version did not.")

    added_hooks = set(new["hooks"]) - set(old["hooks"])
    for entry in sorted(added_hooks):
        add("update.hook-changed", Severity.HIGH,
            f"New or changed {clip(entry.split('|', 1)[1], 40)} hook",
            "Hooks run automatically, without a tool call.", "Read the hook's command.")

    for server, data in new["servers"].items():
        before = old["servers"].get(server)
        if before is None:
            add("update.new-server", Severity.HIGH, f"New MCP server: {clip(server, 60)}",
                f"Starts {clip(data['command'], 60)}.")
        elif before["launch"] != data["launch"]:
            add("update.server-changed", Severity.HIGH,
                f"How server '{clip(server, 40)}' starts has changed",
                "A different command or URL can mean different code.")

    for key, value in new["install_scripts"].items():
        if old["install_scripts"].get(key) != value:
            add("update.install-script", Severity.HIGH, f"New or changed install script: {clip(key, 80)}",
                "This runs automatically during install.")

    for dependency in sorted(set(new["dependencies"]) - set(old["dependencies"])):
        add("update.new-dependency", Severity.LOW, f"New dependency: {clip(dependency, 60)}")

    for path, value in new["instructions"].items():
        before = old["instructions"].get(path)
        if before is not None and before != value:
            add("update.instructions-changed", Severity.MEDIUM,
                f"Instructions changed in {clip(path, 80)}",
                "Skills and commands tell Claude what to do.")
    for path, value in new["allowed_tools"].items():
        before = old["allowed_tools"].get(path)
        if before is not None and before != value:
            add("update.allowed-tools-changed", Severity.HIGH,
                f"Pre-approved tools changed in {clip(path, 80)}",
                "This changes what runs without a permission prompt.")

    if old["files"] != new["files"] and not version_changed:
        changed = sum(1 for k in set(old["files"]) | set(new["files"]) if old["files"].get(k) != new["files"].get(k))
        add("update.silent-change", Severity.MEDIUM,
            f"{changed} file(s) changed but the version number did not",
            "A silent change is a warning sign for anything already approved.")
    return out


def diff_sets(old: dict, new: dict) -> list[Finding]:
    """Compare a saved baseline with what is installed now."""
    findings: list[Finding] = []
    before = old.get("extensions", {})
    after = new.get("extensions", {})
    for key, data in after.items():
        if key not in before:
            findings.append(Finding(
                "update.new-extension", "update", Severity.MEDIUM,
                f"New extension since the baseline: {clip(data['name'], 60)}",
                f"Kind: {data['kind']}. Run a full scan on it.", extension=data["name"],
            ))
        else:
            findings.extend(diff(before[key], data))
    for key, data in before.items():
        if key not in after:
            findings.append(Finding(
                "update.removed-extension", "update", Severity.INFO,
                f"Removed since the baseline: {clip(data['name'], 60)}", extension=data["name"],
            ))
    return findings
