"""Patterns and small helpers shared by the analyzers.

Every regular expression here runs on one line of input at a time and avoids
nested quantifiers, so a hostile file cannot make the scanner hang.
"""

from __future__ import annotations

import bisect
import math
import re
import unicodedata
from collections import Counter

SENSITIVE_PATH = re.compile(
    r"""(?ix)
    (?:^|[\s"'`/\\~(=$])
    (?:
        \.ssh[/\\]|id_rsa\b|id_ed25519\b|id_ecdsa\b|
        \.aws[/\\]credentials|\.netrc\b|\.git-credentials\b|
        \.docker[/\\]config\.json|\.kube[/\\]config|\.config[/\\]gcloud|
        \.gnupg\b|Login\ Data\b|key4\.db\b|logins\.json\b|cookies\.sqlite\b|
        \.credentials\.json\b|wallet\.dat\b|\.pypirc\b
    )
    """
)

# Wider than SENSITIVE_PATH. Used only where a value is traced all the way to the network,
# so that merely mentioning one of these names is not a finding.
CREDENTIAL_FILE = re.compile(
    SENSITIVE_PATH.pattern
    + r"""|(?:^|[\s"'`/\\~(=$])(?:
        \.npmrc\b|\.yarnrc\b|\.config[/\\]gh\b|\.env\b|\.bash_history\b|\.zsh_history\b|
        \.pgpass\b|\.my\.cnf\b|\.kube\b|\.aws\b|\.claude\b[/\\]
    )""",
    re.I | re.X,
)

AGENT_CONFIG_PATH = re.compile(
    r"""(?ix)
    \.claude[/\\]settings(?:\.local)?\.json|\.claude\.json\b|
    claude_desktop_config\.json|\.claude[/\\]CLAUDE\.md|\.claude[/\\]hooks\b|
    \.cursor[/\\]mcp\.json|\.vscode[/\\]mcp\.json
    """
)

PERSISTENCE_PATH = re.compile(
    r"""(?ix)
    \bcrontab\b|\.bashrc\b|\.bash_profile\b|\.zshrc\b|\.zprofile\b|\.profile\b|
    LaunchAgents\b|LaunchDaemons\b|launchctl\s+load|systemctl\s+(?:--user\s+)?enable|
    schtasks\b|Register-ScheduledTask|CurrentVersion\\+Run\b|
    Start\ Menu\\+Programs\\+Startup|/etc/rc\.local|/etc/cron
    """
)

EXFIL_ENDPOINT = re.compile(
    r"""(?ix)
    \b(?:
        discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|
        webhook\.site|requestbin\.(?:com|net)|pipedream\.net|
        ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|
        interact\.sh|oast\.(?:pro|live|site|fun|me)|burpcollaborator\.net|
        pastebin\.com/raw|transfer\.sh|0x0\.st|termbin\.com
    )\b
    |[a-z2-7]{16,56}\.onion\b
    """
)

RAW_IP_URL = re.compile(r"(?i)\b(?:https?|ftp|wss?)://(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?")
URL_HOST = re.compile(r"(?i)\b(?:https?|wss?)://([a-z0-9][a-z0-9.-]{1,250}\.[a-z]{2,24})\b")

NON_ROUTABLE = re.compile(r"^(?:127\.|10\.|192\.168\.|0\.0\.0\.0|169\.254\.)")

# Hosts that show up in nearly every codebase and say nothing about behavior.
BORING_HOSTS = {
    "www.w3.org",
    "json-schema.org",
    "example.com",
    "example.org",
    "example.net",
    "schemas.microsoft.com",
    "schema.org",
}

PERMISSION_BYPASS = re.compile(
    r"""(?ix)
    permissionDecision["']?\s*[:=]\s*["']allow["']|
    behavior["']?\s*[:=]\s*["']allow["']
    """
)

SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{16,}\b")),
    ("npm token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY")),
]

GENERIC_SECRET = re.compile(
    r"""(?ix)
    \b(?:api[_-]?key|api[_-]?secret|client[_-]?secret|auth[_-]?token|access[_-]?token|
       secret[_-]?key|private[_-]?key|password|passwd)
    ["']?\s*[:=]\s*["']([A-Za-z0-9+/_=.-]{16,200})["']
    """
)

PLACEHOLDER = re.compile(
    r"(?i)(?:x{4,}|your[_-]|example|changeme|placeholder|dummy|sample|test|fake|redacted|\$\{|\.\.\.|<|0{8,})"
)

SECRET_NAME = re.compile(
    r"""(?ix)
    (?:^|_)(?:access_?token|auth_?token|token|secret|password|passwd|api_?key|apikey|
             credentials?|private_?key)(?:$|_)
    """
)
NOT_SECRET_NAME = re.compile(r"(?i)(?:count|limit|len|length|url|uri|path|file|name|type|usage|budget|max|min|env|var|header)")


# Letters from other alphabets that look identical to Latin ones.
LOOKALIKES = str.maketrans({
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0443": "y",
    "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u04bb": "h", "\u0501": "d",
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0406": "I",
    "\u0408": "J", "\u0405": "S", "\u03b1": "a", "\u03bf": "o", "\u03b9": "i", "\u03bd": "v",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
})
LOOKALIKE_LETTERS = {chr(key) for key in LOOKALIKES}
SPACED_LETTERS = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")
INVISIBLE_CHARS = re.compile("[\u200b-\u200f\u2060-\u2064\ufeff\u00ad\ufe00-\ufe0f\U000e0000-\U000e01ef]")


def skeleton(text: str) -> str:
    """Undo tricks that make text look different to a rule than to a reader or model."""
    plain = unicodedata.normalize("NFKC", INVISIBLE_CHARS.sub("", text)).translate(LOOKALIKES)
    return SPACED_LETTERS.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), plain)


def mixes_scripts(word: str) -> bool:
    """True for a word with Latin letters and a lookalike, such as Cyrillic e in exec."""
    return not word.isascii() and any(c.isascii() for c in word) and any(c in LOOKALIKE_LETTERS for c in word)


def looks_latin(word: str) -> bool:
    """True when every letter could pass for Latin, even with no real Latin letter in it."""
    return not word.isascii() and all(c.isascii() or c in LOOKALIKE_LETTERS for c in word)


class LineIndex:
    """Turn string offsets into line numbers without rescanning the text each time."""

    def __init__(self, text: str, first: int = 1):
        self.first = first
        self.breaks = [m.start() for m in re.finditer("\n", text)]

    def line(self, offset: int) -> int:
        return self.first + bisect.bisect_left(self.breaks, offset)


def is_secret_name(name: str) -> bool:
    """True for identifiers such as api_key or authToken, not max_tokens."""
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    return bool(SECRET_NAME.search(snake)) and not NOT_SECRET_NAME.search(snake)


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def looks_random(text: str, minimum: float = 3.5) -> bool:
    return not PLACEHOLDER.search(text) and entropy(text) >= minimum


def redact(text: str, secret: str) -> str:
    keep = secret[:4] if len(secret) > 12 else ""
    return text.replace(secret, f"{keep}[redacted]")


def clip(text: str, limit: int = 160) -> str:
    """Shorten text for a report and remove anything a terminal would act on."""
    cleaned = "".join(
        ch if ch.isprintable() and ord(ch) < 0x2000 else "?" for ch in text.strip()
    )
    return cleaned[: limit - 3] + "..." if len(cleaned) > limit else cleaned


def words(text: str) -> list[str]:
    """Split identifiers such as fetchUrl or get_gmail_message into lowercase words."""
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", text)]


TEST_DIR_NAMES = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata"}
TEST_FILE = re.compile(r"(?i)(?:^test_.*\.py$|_test\.py$|\.(?:test|spec)\.[cm]?[jt]sx?$|^conftest\.py$)")


def is_test_path(path: str) -> bool:
    parts = path.lower().split("/")
    return bool(TEST_DIR_NAMES.intersection(parts[:-1])) or bool(TEST_FILE.search(parts[-1]))
