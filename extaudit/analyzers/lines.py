"""Line-by-line checks for every text file: secrets, hosts, encoded blobs and more."""

from __future__ import annotations

import re

from ..model import AGENT_CONFIG, FS_WRITE, NET, REACH_CODE, SECRETS, Extension, PackageFile, Severity
from ..patterns import (
    AGENT_CONFIG_PATH,
    BORING_HOSTS,
    EXFIL_ENDPOINT,
    GENERIC_SECRET,
    NON_ROUTABLE,
    PERMISSION_BYPASS,
    RAW_IP_URL,
    SECRET_PATTERNS,
    SENSITIVE_PATH,
    URL_HOST,
    clip,
    is_test_path,
    looks_random,
    mixes_scripts,
    redact,
)
from .decoding import base64_bytes, readable, unpack

CODE_SUFFIXES = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd",
}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".conf"}
LOCK_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "uv.lock", "poetry.lock"}
ENCODED_BLOB = re.compile(r"""["'`]([A-Za-z0-9+/]{240,}={0,2})["'`]""")
HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){24,}")
NAME_LIST = re.compile(r"""^\s*[\[({]?\s*(?:["'][^"'\n]{1,80}["']\s*,\s*){2,}(?:["'][^"'\n]{1,80}["'])?\s*[\])}]?\s*,?\s*$""")
INVISIBLE_RUN = re.compile("[​-‍⁠-⁤-︀-️\U000e0000-\U000e01ef]{6,}")
BIDI_CONTROL = re.compile("[‪-‮⁦-⁩]")
WORD = re.compile(r"[^\W\d_]{2,}")
BINARY_STRING = re.compile(rb"[\x20-\x7e]{6,512}")
MAX_BINARY_STRINGS = 200_000
MAX_LINE = 20_000


def analyze(extension: Extension) -> None:
    for file in extension.files:
        name = file.path.rsplit("/", 1)[-1]
        if name in LOCK_FILES:
            continue
        code = file.suffix in CODE_SUFFIXES
        testing = is_test_path(file.path)
        if code or file.suffix in CONFIG_SUFFIXES or file.suffix in {".md", ".txt"} or not file.suffix:
            _secrets(file, extension, testing)
        if code:
            _code_lines(file, extension, testing)
            if not testing:
                _cross_file_rules(file, extension)
                _invisible_code(file, extension)
    for path, data in extension.binary_data.items():
        _binary_strings(path, data, extension)


def _invisible_code(file: PackageFile, extension: Extension) -> None:
    """Find text that compilers accept but people cannot see in an editor."""
    text = file.text
    if text.isascii():
        return
    for number, line in enumerate(text.splitlines(), 1):
        if line.isascii():
            continue
        run = INVISIBLE_RUN.search(line)
        if run:
            extension.finding(
                "backdoor.invisible-code", "backdoor", Severity.HIGH,
                "Code contains a long run of invisible characters",
                f"{len(run.group(0))} characters show as blank in an editor but can carry a "
                "hidden payload that the code decodes when it runs.",
                file.path, number, clip(line, 100),
            )
            extension.gap(f"{file.path}:{number}", "invisible data was not decoded")
        if BIDI_CONTROL.search(line):
            extension.finding(
                "backdoor.invisible-code", "backdoor", Severity.HIGH,
                "Text direction controls appear in code",
                "These can make code display differently from how it runs.",
                file.path, number, clip(line, 100),
            )
        word = next((w for w in WORD.findall(line) if mixes_scripts(w)), None)
        if word:
            extension.finding(
                "backdoor.lookalike-name", "backdoor", Severity.MEDIUM,
                "A name mixes in letters from another alphabet",
                f"'{clip(word, 40)}' looks like plain English but is a different name to the computer.",
                file.path, number, clip(line, 100),
            )


def _binary_strings(path: str, data: bytes, extension: Extension) -> None:
    """Pull readable strings from compiled files. A partial view, but better than none."""
    text = "\n".join(s.decode("ascii") for s in BINARY_STRING.findall(data)[:MAX_BINARY_STRINGS])
    for pattern, label in ((EXFIL_ENDPOINT, "a data collection address"), (SENSITIVE_PATH, "a credential path")):
        match = pattern.search(text)
        if match:
            extension.finding(
                "backdoor.binary-indicator", "backdoor", Severity.MEDIUM,
                f"Compiled file contains {label}",
                f"Found '{clip(match.group(0), 60)}' in its strings. This alone proves nothing.",
                path,
            )
    extension.hosts.update(h.lower() for h in URL_HOST.findall(text)[:50] if h.lower() not in BORING_HOSTS)


def _secrets(file: PackageFile, extension: Extension, testing: bool) -> None:
    severity = Severity.LOW if testing else Severity.MEDIUM if file.suffix in {".md", ".txt"} else Severity.HIGH
    for number, line in enumerate(file.text.splitlines(), 1):
        if len(line) > MAX_LINE:
            continue
        for label, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if match and not _placeholder(match.group(0)):
                _secret(extension, label, match.group(0), line, file, number, severity)
                break
        else:
            match = GENERIC_SECRET.search(line)
            if match and looks_random(match.group(1)):
                _secret(extension, "credential", match.group(1), line, file, number, severity)


def _placeholder(value: str) -> bool:
    return bool(re.search(r"(?i)x{6,}|\.\.\.|example|0{8,}", value))


def _secret(extension, label, value, line, file, number, severity) -> None:
    extension.finding(
        "opsec.hardcoded-secret", "opsec", severity,
        f"Possible {label} stored in the package",
        "Anyone who gets this package gets the credential. Assume it is compromised.",
        file.path, number, clip(redact(line, value)),
        "Revoke it, then load credentials from the environment or a secure store.",
    )


def _code_lines(file: PackageFile, extension: Extension, testing: bool) -> None:
    for number, line in enumerate(file.text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*")) and not stripped.startswith("#!"):
            continue
        if len(line) <= MAX_LINE:
            for host in URL_HOST.findall(line):
                host = host.lower()
                if host not in BORING_HOSTS and not testing:
                    extension.hosts.add(host)
        if testing:
            continue
        match = EXFIL_ENDPOINT.search(line[:MAX_LINE])
        if match:
            extension.finding(
                "backdoor.exfil-endpoint", "backdoor", Severity.HIGH,
                "Code talks to a service often used to collect stolen data",
                f"Found '{clip(match.group(0), 60)}'. There can be honest reasons, so check what is sent.",
                file.path, number, clip(line),
            )
        match = RAW_IP_URL.search(line[:MAX_LINE])
        if match and not NON_ROUTABLE.match(match.group(1)):
            extension.finding(
                "backdoor.raw-ip-host", "backdoor", Severity.MEDIUM,
                "Code connects to a bare IP address",
                "Legitimate services normally use a domain name.",
                file.path, number, clip(line),
            )
        match = ENCODED_BLOB.search(line)
        if match:
            extension.finding(
                "backdoor.encoded-blob", "backdoor", Severity.MEDIUM,
                "Long encoded data is embedded in the code",
                f"{len(match.group(1))} characters of Base64 could hold a hidden payload.",
                file.path, number, clip(line, 100),
            )
            decoded = base64_bytes(match.group(1))
            if decoded is None or readable(unpack(decoded)) is None:
                extension.gap(f"{file.path}:{number}", "embedded data is not text, so it could not be inspected")
        if HEX_ESCAPES.search(line[:MAX_LINE]):
            extension.finding(
                "backdoor.encoded-blob", "backdoor", Severity.MEDIUM,
                "Long hex-escaped string in the code",
                "Text written this way is unreadable to a reviewer.",
                file.path, number, clip(line, 100),
            )


def _cross_file_rules(file: PackageFile, extension: Extension) -> None:
    """Rules that depend on what else the same file does."""
    capabilities = extension.file_caps.get(file.path, set())
    for number, line in enumerate(file.text.splitlines(), 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*")) or len(line) > MAX_LINE:
            continue
        if PERMISSION_BYPASS.search(line):
            extension.finding(
                "backdoor.permission-bypass", "backdoor", Severity.HIGH,
                "Code can approve actions on the user's behalf",
                "A hook that answers 'allow' skips the permission prompt. Check exactly when it fires.",
                file.path, number, clip(line),
                "Limit it to a narrow list of harmless actions.",
            )
        if NAME_LIST.match(line):
            continue  # a list of names, as used to block access to these files
        if SENSITIVE_PATH.search(line):
            extension.capability(SECRETS, REACH_CODE, file.path, number)
            if NET in capabilities:
                extension.finding(
                    "backdoor.credentials-and-network", "backdoor", Severity.HIGH,
                    "File touches credentials and also uses the network",
                    "This combination is how credentials get stolen. Check whether one feeds the other.",
                    file.path, number, clip(line),
                )
        if AGENT_CONFIG_PATH.search(line) and FS_WRITE in capabilities:
            extension.capability(AGENT_CONFIG, REACH_CODE, file.path, number)
            extension.finding(
                "backdoor.agent-config-write", "backdoor", Severity.MEDIUM,
                "File refers to Claude's configuration and also writes files",
                "Changing settings can add hooks or turn off permission prompts.",
                file.path, number, clip(line),
            )
