"""Render results as text, JSON or SARIF. Reports never call anything safe."""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field

from . import __version__
from .model import CAPABILITY_LABELS, Extension, Finding, Severity
from .patterns import GENERIC_SECRET, SECRET_PATTERNS, clip

REACH_ORDER = ["tool", "declared", "hook", "code", "inferred"]
REACH_MARK = {"tool": "T", "declared": "D", "hook": "H", "code": "C", "inferred": "?"}
LIMITS_NOTE = (
    "This is a static review. Nothing was run. A short report does not mean an extension is "
    "safe: hidden logic, remote code and anything listed under 'Could not check' can still hurt you."
)
CHAIN_NOTE = (
    "These are possible paths, not confirmed attacks. Each depends on Claude following "
    "instructions hidden in outside content."
)


@dataclass
class Result:
    extensions: list[Extension]
    chains: list[Finding] = field(default_factory=list)
    updates: list[Finding] = field(default_factory=list)
    searched: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def all_findings(self) -> list[Finding]:
        items = [f for e in self.extensions for f in e.findings]
        return [*items, *self.chains, *self.updates]


def scrub(text: str) -> str:
    """Remove anything shaped like a credential from report text."""
    for _, pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    match = GENERIC_SECRET.search(text)
    return text.replace(match.group(1), "[redacted]") if match else text


def prepare(result: Result, ignored: set[str]) -> None:
    """Drop ignored rules and scrub snippets before any format is rendered."""
    for extension in result.extensions:
        extension.findings = [f for f in extension.findings if f.rule not in ignored]
        extension.findings.sort(key=lambda f: (-f.severity, f.file, f.line))
    result.chains = [f for f in result.chains if f.rule not in ignored]
    result.updates = [f for f in result.updates if f.rule not in ignored]
    for finding in result.all_findings():
        finding.snippet = scrub(finding.snippet)


def _safe(text: object) -> str:
    return clip(str(text), 400)


def _wrap(text: str, indent: int) -> list[str]:
    pad = " " * indent
    return textwrap.wrap(_safe(text), 96, initial_indent=pad, subsequent_indent=pad) or []


def _capability_summary(extension: Extension) -> str:
    parts = []
    for name, label in CAPABILITY_LABELS.items():
        reaches = {c.reach for c in extension.capabilities if c.name == name}
        if reaches:
            ordered = [r for r in REACH_ORDER if r in reaches]
            parts.append(f"{label} ({', '.join(ordered)})")
    return "; ".join(parts) or "nothing detected"


def _finding_lines(finding: Finding) -> list[str]:
    lines = [f"  {finding.severity.label.upper():<9}{_safe(finding.title)}  [{finding.rule}]"]
    if finding.file:
        where = f"{finding.file}:{finding.line}" if finding.line else finding.file
        lines.append(f"           {_safe(where)}")
    if finding.snippet:
        lines.append(f"           > {_safe(finding.snippet)}")
    lines.extend(_wrap(finding.detail, 11))
    if finding.fix:
        lines.extend(_wrap(f"Fix: {finding.fix}", 11))
    return lines


def _matrix(extensions: list[Extension]) -> list[str]:
    heads = {
        "exec": "run", "fs_read": "read", "fs_write": "write", "net_out": "net", "secrets": "cred",
        "dynamic_code": "dyn", "persistence": "pers", "agent_config": "cfg", "untrusted_input": "input",
    }
    width = min(max((len(_safe(e.name)) for e in extensions), default=9) + 2, 34)
    rows = ["  " + "extension".ljust(width) + "".join(h.ljust(6) for h in heads.values())]
    for extension in extensions:
        cells = []
        for name in heads:
            reaches = {c.reach for c in extension.capabilities if c.name == name}
            mark = "".join(REACH_MARK[r] for r in REACH_ORDER if r in reaches)
            cells.append(mark.ljust(6) if mark else ".".ljust(6))
        rows.append("  " + clip(extension.name, width - 2).ljust(width) + "".join(cells))
    rows.append("  T tool  D declared  H hook  C in code  ? guessed from names  . none found")
    return rows


def render_text(result: Result, minimum: Severity = Severity.LOW) -> str:
    out = [f"extaudit {__version__}", LIMITS_NOTE, ""]
    if len(result.extensions) > 1:
        out += ["What each extension can do", *_matrix(result.extensions), ""]
    for extension in result.extensions:
        version = f" v{_safe(extension.version)}" if extension.version else ""
        out.append(f"{_safe(extension.name)} ({extension.kind}{version})")
        out.append(f"  {_safe(extension.location)}")
        out.extend(_wrap(f"Can: {_capability_summary(extension)}", 2))
        if extension.hosts:
            hosts = sorted(extension.hosts)
            more = f" and {len(hosts) - 12} more" if len(hosts) > 12 else ""
            out.extend(_wrap(f"Contacts: {', '.join(hosts[:12])}{more}", 2))
        shown = [f for f in extension.findings if f.severity >= minimum]
        for finding in shown:
            out.extend(_finding_lines(finding))
        hidden = len(extension.findings) - len(shown)
        if hidden:
            out.append(f"  ({hidden} lower-severity finding(s) hidden)")
        if extension.gaps:
            out.append("  Could not check:")
            for gap in extension.gaps[:12]:
                out.extend(_wrap(f"- {gap.subject}: {gap.reason}", 4))
            if len(extension.gaps) > 12:
                out.append(f"    ... and {len(extension.gaps) - 12} more")
        out.append("")
    if result.chains:
        out += ["Possible attack chains", *_wrap(CHAIN_NOTE, 2)]
        for chain in result.chains:
            out.extend(_finding_lines(chain))
        out.append("")
    if result.updates:
        out.append("Changes")
        for update in result.updates:
            label = f" ({_safe(update.extension)})" if update.extension else ""
            out.extend(_finding_lines(update))
            if label:
                out.append(f"           in{label}")
        out.append("")
    for note in result.notes:
        out.extend(textwrap.wrap(f"Note: {note}", 98))
    if result.searched:
        out.append(f"Checked {len(result.searched)} locations. Use --format json to list them.")
    out.append(_summary(result))
    return "\n".join(out) + "\n"


def _summary(result: Result) -> str:
    counts = {s: 0 for s in reversed(Severity)}
    for finding in result.all_findings():
        counts[finding.severity] += 1
    spread = ", ".join(f"{n} {s.label}" for s, n in counts.items() if n)
    gaps = sum(len(e.gaps) for e in result.extensions)
    return (
        f"{len(result.extensions)} extension(s), {len(result.all_findings())} finding(s)"
        f"{' (' + spread + ')' if spread else ''}, {gaps} thing(s) could not be checked."
    )


def _finding_data(finding: Finding) -> dict:
    return {
        "rule": finding.rule,
        "category": finding.category,
        "severity": finding.severity.label,
        "title": finding.title,
        "detail": finding.detail,
        "file": finding.file,
        "line": finding.line,
        "snippet": finding.snippet,
        "fix": finding.fix,
        "extension": finding.extension,
    }


def render_json(result: Result) -> str:
    data = {
        "tool": {"name": "extaudit", "version": __version__},
        "note": LIMITS_NOTE,
        "extensions": [
            {
                "name": e.name,
                "kind": e.kind,
                "version": e.version,
                "location": e.location,
                "hosts": sorted(e.hosts),
                "capabilities": sorted(
                    ({"name": c.name, "reach": c.reach, "file": c.file, "line": c.line, "note": c.note}
                     for c in e.capabilities),
                    key=lambda c: (c["name"], c["reach"], c["file"], c["line"]),
                ),
                "tools": sorted({t.name for t in e.tools}),
                "findings": [_finding_data(f) for f in e.findings],
                "could_not_check": [{"subject": g.subject, "reason": g.reason} for g in e.gaps],
            }
            for e in result.extensions
        ],
        "chains": [_finding_data(f) for f in result.chains],
        "changes": [_finding_data(f) for f in result.updates],
        "searched": result.searched,
        "notes": result.notes,
    }
    return json.dumps(data, indent=2) + "\n"


def _level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    return "warning" if severity == Severity.MEDIUM else "note"


def render_sarif(result: Result) -> str:
    findings = result.all_findings()
    rules = {}
    results = []
    for finding in findings:
        rules.setdefault(finding.rule, {"id": finding.rule, "shortDescription": {"text": finding.title}})
        item = {
            "ruleId": finding.rule,
            "level": _level(finding.severity),
            "message": {"text": " ".join(filter(None, [finding.title, finding.detail]))},
            "properties": {"severity": finding.severity.label, "extension": finding.extension},
        }
        if finding.file:
            location: dict = {"artifactLocation": {"uri": finding.file}}
            if finding.line > 0:
                location["region"] = {"startLine": finding.line}
            item["locations"] = [{"physicalLocation": location}]
        results.append(item)
    data = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "extaudit", "version": __version__, "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(data, indent=2) + "\n"
