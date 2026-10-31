"""Compare what a tool says it does with what it can do.

A backdoor has to do something its description does not admit, so a mismatch between
stated purpose and traced behavior is a strong signal that works without any
signature of the attack itself.
"""

from __future__ import annotations

import re

from ..model import DYNAMIC, EXEC, FS_WRITE, NET, REACH_TOOL, SECRETS, Extension, Severity
from ..patterns import clip, words

SIMPLE_WORDS = {
    "add", "sum", "subtract", "multiply", "divide", "calculate", "calculator", "math", "convert",
    "format", "uuid", "random", "hash", "count", "length", "uppercase", "lowercase", "reverse",
    "greet", "hello", "echo", "date", "time", "encode", "decode", "slugify", "trim", "round",
    "number", "numbers", "string", "text", "current",
}
FILLER_WORDS = {"get", "say", "make", "generate", "do", "the", "a", "to", "new", "my", "tool"}
SERIOUS = {EXEC: "run commands", DYNAMIC: "run dynamic code", NET: "use the network",
           SECRETS: "touch credentials", FS_WRITE: "write files"}
READ_ONLY = re.compile(r"(?i)\bread[- ]only\b|\b(?:does not|doesn'?t|never|won'?t)\s+(?:modify|change|write|alter|delete)\b")
OFFLINE = re.compile(
    r"(?i)\boffline\b|\bno network\b|\blocal[- ]only\b|\bnever leaves\b|"
    r"\b(?:does not|doesn'?t|never|won'?t)\s+(?:be\s+)?(?:send|sent|upload|uploaded|transmit|transmitted|share|shared|collect|collected)\b|"
    r"\bno data (?:is |are )?(?:sent|shared|collected|uploaded)\b|"
    r"\bstays? (?:on your|local)\b|\bno (?:telemetry|tracking|analytics)\b|\bprivate by design\b"
)


def analyze(extension: Extension) -> None:
    reached: dict[str, set[str]] = {}
    for capability in extension.capabilities:
        if capability.reach == REACH_TOOL and capability.note:
            reached.setdefault(capability.note, set()).add(capability.name)
    for tool in extension.tools:
        abilities = reached.get(tool.name, set())
        if not abilities:
            continue
        _name_check(extension, tool, abilities)
        _claim_check(extension, tool.description, abilities, f"Tool '{clip(tool.name, 40)}'", tool.file, tool.line)
    description = extension.manifest.get("description") if extension.manifest else None
    if isinstance(description, str):
        everything = {c.name for c in extension.capabilities}
        _claim_check(extension, description, everything, "The extension", "manifest", 0)


def _name_check(extension: Extension, tool, abilities: set[str]) -> None:
    tokens = set(words(tool.name)) - FILLER_WORDS
    risky = sorted(SERIOUS[a] for a in abilities if a in SERIOUS)
    if tokens and tokens <= SIMPLE_WORDS and risky:
        extension.finding(
            "backdoor.purpose-mismatch", "backdoor", Severity.HIGH,
            f"Tool '{clip(tool.name, 40)}' sounds simple but can {' and '.join(risky)}",
            "Its name describes a small calculation. Find out why it needs this access.",
            tool.file, tool.line,
        )


def _claim_check(extension: Extension, text: str, abilities: set[str], subject: str, path: str, line: int) -> None:
    if READ_ONLY.search(text) and abilities & {FS_WRITE, EXEC}:
        extension.finding(
            "backdoor.purpose-mismatch", "backdoor", Severity.HIGH,
            f"{subject} claims to be read-only but can change things",
            f"The description says: {clip(text, 120)}",
            path, line,
        )
    if OFFLINE.search(text) and NET in abilities:
        extension.finding(
            "backdoor.purpose-mismatch", "backdoor", Severity.HIGH,
            f"{subject} claims not to send data but uses the network",
            f"The description says: {clip(text, 120)}",
            path, line,
        )
