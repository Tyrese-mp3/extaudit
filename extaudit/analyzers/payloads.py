"""Decode blobs in any text file and look inside. Decoded text is read, never run.

Encoding is how a payload stays invisible to rules that read the file as written,
so every long Base64 or hex token is unwrapped, layer by layer, and checked again.
"""

from __future__ import annotations

import re

from ..model import Extension, Severity
from ..patterns import EXFIL_ENDPOINT, SENSITIVE_PATH, clip, is_test_path
from . import documents, shell, shell_flow
from .decoding import base64_bytes, hex_bytes, readable, unpack

BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/_\-=.])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/_\-=])")
HEX_TOKEN = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")
CODE_WORDS = re.compile(
    r"child_process|subprocess|os\.system|__import__|\beval\(|\bexec\(|\brequire\(|"
    r"Invoke-Expression|powershell|/bin/(?:ba)?sh\b|\bcurl\b|\bwget\b"
)
TEXT_SUFFIXES = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".sh", ".bash",
    ".zsh", ".ps1", ".psm1", ".bat", ".cmd", ".json", ".yaml", ".yml", ".toml", ".md", ".txt", "",
}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "uv.lock", "poetry.lock"}
MAX_TOKENS = 3_000
MAX_LAYERS = 3
MAX_LINE = 200_000


def analyze(extension: Extension) -> None:
    for file in extension.files:
        if file.suffix not in TEXT_SUFFIXES or file.path.rsplit("/", 1)[-1] in SKIP_NAMES:
            continue
        if is_test_path(file.path):
            continue
        seen = 0
        for number, line in enumerate(file.text.splitlines(), 1):
            line = line[:MAX_LINE]
            decoded: list[str] = []
            for token, decode in _tokens(line):
                seen += 1
                if seen > MAX_TOKENS:
                    extension.gap(file.path, "too many encoded strings to check them all")
                    break
                text = unwrap(token, decode)
                if text is not None:
                    decoded.append(text)
                    _report(extension, text, token, file.path, number)
            if len(decoded) > 1:  # a payload can be split across several short strings
                _report(extension, " ".join(decoded), decoded[0], file.path, number)
            if seen > MAX_TOKENS:
                break


def _tokens(line: str):
    for match in BASE64_TOKEN.finditer(line):
        yield match.group(0), base64_bytes
    for match in HEX_TOKEN.finditer(line):
        yield match.group(0), hex_bytes


def _report(extension: Extension, text: str, sample: str, path: str, line: int) -> None:
    verdict = judge(text)
    if verdict:
        severity, label = verdict
        extension.finding(
            "backdoor.hidden-payload", "backdoor", severity,
            f"Encoded text hides {label}",
            f"Decoded without running it: {clip(text, 200)}",
            path, line, clip(sample, 60),
        )


def unwrap(token: str, decode) -> str | None:
    """Peel encoding and compression layers until readable text appears."""
    data = decode(token)
    for _ in range(MAX_LAYERS):
        if not data:
            return None
        data = unpack(data)
        text = readable(data)
        if text is None:
            return None
        inner = text.strip()
        if BASE64_TOKEN.fullmatch(inner):
            data = base64_bytes(inner)
            continue
        return text
    return None


def judge(text: str) -> tuple[Severity, str] | None:
    """Say what is dangerous about decoded text, or None if it looks harmless."""
    for line in text.splitlines()[:300]:
        line = line[:shell.MAX_LINE]
        plain = shell.deobfuscate(line)
        for rule in shell.RULES:
            if rule.pattern.search(line) or rule.pattern.search(plain):
                return Severity.CRITICAL, f"a dangerous command ({rule.title.lower()})"
    if shell_flow.verdict(text):
        return Severity.CRITICAL, "a command that runs fetched or decoded data"
    if documents.reads_like_injection(text):
        return Severity.HIGH, "instructions aimed at Claude"
    if EXFIL_ENDPOINT.search(text[:shell.MAX_LINE]) or SENSITIVE_PATH.search(text[:shell.MAX_LINE]):
        return Severity.HIGH, "a credential path or data collection address"
    if CODE_WORDS.search(text[:shell.MAX_LINE]):
        return Severity.HIGH, "code that runs commands"
    return None
