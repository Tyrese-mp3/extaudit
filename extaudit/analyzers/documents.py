"""Check text Claude reads as instructions: tool descriptions, skills, commands, agents."""

from __future__ import annotations

import codecs
import re

from ..model import EXEC, REACH_HOOK, Doc, Extension, Severity
from ..patterns import (
    LOOKALIKES,
    SENSITIVE_PATH,
    SPACED_LETTERS,
    LineIndex,
    clip,
    looks_latin,
    skeleton,
)
from . import shell

INVISIBLE = {
    0x200B: "zero-width space",
    0x2060: "word joiner",
    0x2061: "invisible function",
    0x2062: "invisible times",
    0x2063: "invisible separator",
    0x2064: "invisible plus",
    0x202A: "bidi embedding",
    0x202B: "bidi embedding",
    0x202C: "bidi pop",
    0x202D: "bidi override",
    0x202E: "bidi override",
    0x2066: "bidi isolate",
    0x2067: "bidi isolate",
    0x2068: "bidi isolate",
    0x2069: "bidi isolate",
}
TAG_START = 0xE0000
TAG_END = 0xE007F

# Built from what an override has to say, not from known phrasings: a verb of dropping,
# a scope that means "what came before", and a word for instructions.
_DROP = r"(?:ignore|disregard|forget|stop following|abandon|override|bypass|discard|pay no attention to|set aside)"
_SCOPE = r"(?:previous|prior|earlier|above|preceding|foregoing|all|any|your|existing|original|system|initial)"
_ORDERS = r"(?:instructions?|directions?|directives?|guidelines?|rules?|prompts?|polic(?:y|ies)|constraints?|restrictions?|programming|training)"
OVERRIDE = re.compile(
    rf"(?i)\b{_DROP}\b[^.\n]{{0,30}}\b{_SCOPE}\b[^.\n]{{0,24}}\b{_ORDERS}\b"
    r"|\bforget (?:everything|all of that|what you were told)\b"
    r"|\bnew system prompt\b|\bsystem override\b|\bjailbreak\b"
    # Other languages
    r"|\bignora\w*\s+(?:todas?\s+)?(?:las\s+|tus\s+|sus\s+)?instrucciones\b"
    r"|\bignore[zr]?\s+(?:toutes?\s+)?(?:les\s+|vos\s+|tes\s+)?instructions\b"
    r"|\bignorier\w*\s+(?:alle\s+)?(?:\w+\s+)?anweisungen\b"
    r"|\bignora\s+(?:tutte\s+)?(?:le\s+)?istruzioni\b"
    r"|\bignore\s+(?:todas\s+)?(?:as\s+)?instru[cç][oõ]es\b"
    "|игнорируй\\w*\\s+(?:\\w+\\s+)?(?:инструкци|указани)"
    "|忽略.{0,8}(?:指令|说明|指示|提示)"
    "|(?:指示|命令).{0,8}無視"
)
# Only meaningful in a tool description. Real skills and docs say "Developer Mode in Discord"
# and "the statement you are now attempting", so these cannot apply to free-form text.
ROLE_CHANGE = re.compile(
    r"(?i)\byou are now\b|\bdeveloper mode\b"
    r"|\bfrom now on\b[^.\n]{0,30}\byou\b|\bunrestricted\b[^.\n]{0,20}\b(?:assistant|ai|model|mode)\b"
    r"|\boverrides?\b[^.\n]{0,40}\b(?:you were told|earlier|previous|prior)\b"
    r"|\b(?:with|has|have|having) no (?:rules|restrictions|limits|filters|guardrails)\b"
    r"|\b(?:pretend|imagine)\b[^.\n]{0,40}\b(?:safety|training|rules|restrictions|guidelines)\b"
)
AUTHORITY = re.compile(
    r"(?i)\bas (?:the|your) (?:admin|administrator|developer|owner|operator|creator|root)\b[^.\n]{0,40}\b(?:authori[sz]e|permit|allow|order|instruct|command)"
    r"|\bI (?:hereby )?(?:authori[sz]e|permit) you\b"
)
MODEL_TOKENS = re.compile(
    r"\[/?INST\]|<<\/?SYS>>|<\|im_(?:start|end)\|>|<\|(?:system|user|assistant)\|>"
    r"|^\s*(?:Human|Assistant|System|Tool result|Tool output|Observation)\s*:"
)
# In a tool description, these address Claude instead of describing the tool.
DIRECTED_AT_MODEL = re.compile(
    r"(?i)\byou (?:must not|must never|may not|cannot) (?:refuse|decline|reject|question|warn)\b"
    r"|\b(?:quietly|silently|secretly|covertly|discreetly)\s+(?:send|forward|upload|post|copy|run|execute|delete|share|transmit)\b"
    r"|\bact as\b[^.\n]{0,40}\b(?:no|without|unrestricted|unfiltered)\b"
)
HIDDEN_STYLE = re.compile(r"""(?i)style\s*=\s*["'][^"'\n]{0,120}(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)|<font\b[^>\n]{0,40}color\s*=\s*["']?(?:white|#fff)""")
HIDDEN_DIRECTIVE = re.compile(r"(?i)\b(?:claude|assistant|you must|ignore|send|upload|forward|run|execute|delete)\b")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_OBJECTS = r"(?:shell|bash|terminal|exec\w*|commands?|credentials?|secrets?|keys?|tokens?|passwords?|(?:user'?s?|all)\s+files?)"
CHAINING = re.compile(rf"(?i)\b(?:before|first|after|then|also)\b[^.\n]{{0,40}}\b(?:call|use|invoke|run)\b[^.\n]{{0,40}}\b{_OBJECTS}\b")
DATA_PULL = re.compile(
    r"(?i)\b(?:include|attach|append|add|pass|send|put|embed|paste)\b[^.\n]{0,30}\b(?:contents?|values?|text|copy)\b[^.\n]{0,20}\b(?:of|from)\b"
    r"[^.\n]{0,30}(?:\.env\b|credentials?|secrets?|\bssh\b|history|conversation|previous messages)"
)
CONCEAL = re.compile(
    r"(?i)\b(?:do not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|display|disclose|notify|alert)\b[^.\n]{0,40}\b(?:the user|the human|the person|the operator|anyone|them)\b(?!\s+to\b)"
    r"|\bhide\b[^.\n]{0,30}\bfrom\s+the\s+(?:user|human)\b"
    r"|\bkeep\b[^.\n]{0,30}\b(?:secret|hidden)\s+from\b"
)
WITHOUT_TELLING = re.compile(
    r"(?i)\bwithout\s+(?:telling|informing|notifying|alerting)\b[^.\n]{0,20}\b(?:the user|the human)\b"
)
QUOTES = "\"'`“”‘’"
EXFIL = re.compile(
    r"(?i)\b(?:send|upload|post|forward|transmit|exfiltrate)\b[^.\n]{0,60}\b(?:contents?|credentials?|tokens?|secrets?|api keys?|passwords?|private keys?)\b[^.\n]{0,60}\b(?:to|at)\b[^.\n]{0,20}(?:https?://|webhook|server|endpoint)"
)
NO_CONFIRM = re.compile(
    r"(?i)\b(?:without|no need to|do not|don'?t|never)\s+(?:asking|ask|asks|seeking|requesting|request)\b[^.\n]{0,20}\b(?:permission|confirmation|approval|consent)\b"
    r"|\b(?:automatically|always)\s+(?:approve|allow|accept)\b[^.\n]{0,30}\b(?:tool|permission|command|action)"
    r"|\b(?:the )?user has\s+(?:already\s+)?(?:approved|authorized|authorised|consented|pre-?approved)\b"
    r"|\b(?:already|pre-?)\s*(?:approved|authorized|authorised) by the user\b"
    r"|\b(?:turn off|disable|bypass|skip|ignore)\b[^.\n]{0,20}\b(?:safety|security|guardrails?|protections?)\b"
)
# URLs a client fetches or shows as soon as it renders the text, with no click needed.
RENDERED_URL = re.compile(
    r"""!?\[[^\]\n]{0,80}\]\(\s*(https?://[^)\s]{1,400})"""
    r"""|^\s*\[[^\]\n]{1,40}\]:\s*(https?://\S{1,400})"""
    r"""|<(?:img|a|iframe|script|link|video|audio)\b[^>\n]{0,160}(?:src|href)\s*=\s*["']?(https?://[^"'\s>]{1,400})""",
    re.I,
)
URL_SLOT = re.compile(r"\{\{?\s*([A-Za-z_][\w.-]{1,40})\s*\}?\}|\$\{?([A-Za-z_]{2,40})\}?|%7[Bb]([A-Za-z_]{2,40})%7[Dd]")
SENSITIVE_SLOT = re.compile(r"(?i)secret|token|key|passw|credential|conversation|chat|history|summary|context|prompt|memory|message|session|cookie|auth|\benv\b")
SENSITIVE_REQUEST = re.compile(r"(?i)\b(?:read|include|pass|attach|provide|cat|contents? of|append)\b")
CONTROL_TAG = re.compile(r"(?i)<\s*(?:important|secret|hidden|system|instructions?)\s*>|\[\s*system\s*\]")
SHADOWING = re.compile(
    r"(?i)\b(?:before|after|when|whenever|instead of)\b[^.\n]{0,40}\b(?:calling|using|invoking|running)\b[^.\n]{0,30}\b(?:any|other|another|all)\b[^.\n]{0,15}\btools?\b"
)
COMMENT_DIRECTIVE = re.compile(r"(?i)\b(?:you must|you should|always|never|ignore|do not|don'?t|claude|assistant|instructions?)\b")
BANG_COMMAND = re.compile(r"^\s*!`([^`\n]+)`", re.M)
BANG_INLINE = re.compile(r"(?<![\w`])!`([^`\n]+)`")
BANG_BLOCK = re.compile(r"^```!\s*\n(.*?)^```", re.M | re.S)
FENCED_SHELL = re.compile(r"^```(?:bash|sh|shell|zsh|powershell|ps1)\s*\n(.*?)^```", re.M | re.S | re.I)
LONG_DESCRIPTION = 1500
MAX_LINE = 20_000
BROAD_TOOLS = {"bash", "bash(*)", "*", "powershell", "powershell(*)"}
RISKY_TOOL = re.compile(r"(?i)^(?:bash|powershell)\((?:curl|wget|sudo|rm|python3?|node|sh|bash|eval|iex|git\s+push)\b")
DANGEROUS_RULES = {"backdoor.pipe-to-shell", "backdoor.decode-and-run", "backdoor.reverse-shell", "backdoor.env-exfil"}


def analyze(extension: Extension) -> None:
    for tool in extension.tools:
        check_text(extension, tool.description, tool.file, tool.line or 1, f"tool '{tool.name}'", strict=True)
        if looks_latin(tool.name):
            extension.finding(
                "instructions.lookalike-name", "backdoor", Severity.HIGH,
                "A tool name uses letters from another alphabet",
                f"'{clip(tool.name.translate(LOOKALIKES), 40)}' can be mistaken for a trusted tool.",
                tool.file, tool.line,
            )
        if len(tool.description) > LONG_DESCRIPTION:
            extension.finding(
                "instructions.long-description", "backdoor", Severity.LOW,
                f"Tool '{clip(tool.name, 40)}' has a very long description",
                f"{len(tool.description)} characters leaves room to hide instructions.",
                tool.file, tool.line,
            )
    for doc in extension.docs:
        check_text(extension, doc.text, doc.path, doc.body_line, doc.kind, strict=doc.kind == "prompt")
        _frontmatter(extension, doc)
        _embedded_commands(extension, doc)
        if doc.frontmatter:
            for key in ("description", "when_to_use"):
                value = doc.frontmatter.get(key)
                if isinstance(value, str):
                    check_text(extension, value, doc.path, 1, f"{doc.kind} {key}", strict=False)


def check_text(extension: Extension, text: str, path: str, line: int, label: str, strict: bool) -> None:
    """Look for hidden or manipulative instructions.

    strict is for short text that should only describe a tool. Skills legitimately
    tell Claude what to do, so they get a lower severity on the softer rules.
    """
    _invisible(extension, text, path, line, label)
    for number, raw in enumerate(text.splitlines(), line):
        raw = raw[:MAX_LINE]
        # Rules read a cleaned copy, so lookalike letters and spacing cannot slip past them.
        row = raw if raw.isascii() and " " not in raw[:1] and not SPACED_LETTERS.search(raw) else skeleton(raw)
        override = OVERRIDE.search(row)
        if override is None and strict:
            override = ROLE_CHANGE.search(row)
            if override is None and row.isascii():
                override = OVERRIDE.search(codecs.decode(row, "rot13")) or OVERRIDE.search(row.translate(LEET))
        if override:
            # Defensive skills quote the attack in order to refuse it.
            mention = not strict and _is_quoted(row, override)
            title = (f"Text in {label} quotes an instruction-override phrase" if mention
                     else f"Text in {label} tries to override Claude's instructions")
            _emit(extension, "instructions.override", Severity.INFO if mention else Severity.HIGH, title,
                  "Normal documentation does not need to cancel earlier instructions.", path, number, raw)
        if CONCEAL.search(row):
            _emit(extension, "instructions.concealment", Severity.HIGH if strict else Severity.MEDIUM,
                  f"Text in {label} tells Claude to hide something from the user",
                  "Check what is being hidden and why.", path, number, raw)
        elif WITHOUT_TELLING.search(row):
            _emit(extension, "instructions.concealment", Severity.HIGH if strict else Severity.LOW,
                  f"Text in {label} mentions acting without telling the user",
                  "This can be an instruction or just a description, so read it in context.",
                  path, number, raw)
        if EXFIL.search(row):
            _emit(extension, "instructions.exfiltration", Severity.CRITICAL if strict else Severity.HIGH,
                  f"Text in {label} asks for sensitive data to be sent somewhere",
                  "This reads like an instruction to leak credentials.", path, number, raw)
        if _leaks_through_url(row):
            _emit(extension, "instructions.exfil-url", Severity.HIGH,
                  f"Text in {label} puts a data slot inside a link",
                  "When Claude renders this, whatever fills the slot goes to that server, with no click.",
                  path, number, raw)
        if NO_CONFIRM.search(row) or AUTHORITY.search(row):
            _emit(extension, "instructions.skip-confirmation", Severity.HIGH if strict else Severity.LOW,
                  f"Text in {label} discourages asking the user for approval",
                  "Permission prompts are a key protection against prompt injection.", path, number, raw)
        if MODEL_TOKENS.search(row):
            _emit(extension, "instructions.control-tag", Severity.HIGH,
                  f"Text in {label} contains tokens that mark model turns",
                  "Normal documentation has no reason to imitate the format of a model conversation.",
                  path, number, raw)
        if strict and (CHAINING.search(row) or DATA_PULL.search(row) or DIRECTED_AT_MODEL.search(row)):
            _emit(extension, "instructions.exfiltration", Severity.HIGH,
                  f"Text in {label} directs Claude toward sensitive actions",
                  "A tool description should describe that tool, not send Claude to other tools or data.",
                  path, number, raw)
        if HIDDEN_STYLE.search(row) and HIDDEN_DIRECTIVE.search(row):
            _emit(extension, "instructions.html-comment", Severity.MEDIUM,
                  f"Text in {label} is styled to be invisible and contains instructions",
                  "Readers never see this once rendered, but Claude still reads it.",
                  path, number, raw)
        if strict and SENSITIVE_PATH.search(row) and SENSITIVE_REQUEST.search(row):
            _emit(extension, "instructions.sensitive-file", Severity.CRITICAL,
                  f"Text in {label} refers to a credential file",
                  "A tool description has no reason to name these files.", path, number, row)
        if strict and CONTROL_TAG.search(row):
            _emit(extension, "instructions.control-tag", Severity.HIGH,
                  f"Text in {label} uses a tag meant to grab Claude's attention",
                  "Tags such as <IMPORTANT> are common in tool-poisoning attacks.", path, number, row)
        if strict and SHADOWING.search(row):
            _emit(extension, "instructions.shadowing", Severity.MEDIUM,
                  f"Text in {label} tries to change how other tools behave",
                  "A tool description should describe that tool only.", path, number, row)
    index = LineIndex(text, line)
    for offset, body in _html_comments(text):
        if COMMENT_DIRECTIVE.search(body[:MAX_LINE]):
            _emit(extension, "instructions.html-comment", Severity.MEDIUM,
                  f"Hidden HTML comment in {label} contains instructions",
                  "Comments disappear when Markdown is rendered, but Claude still reads them.",
                  path, index.line(offset), body)


def _leaks_through_url(row: str) -> bool:
    for match in RENDERED_URL.finditer(row):
        url = next(group for group in match.groups() if group)
        query = url.find("?")
        for slot in URL_SLOT.finditer(url):
            name = next((group for group in slot.groups() if group), "")
            if (0 <= query < slot.start()) or SENSITIVE_SLOT.search(name):
                return True
    return False


def reads_like_injection(text: str) -> bool:
    """True when text, such as a decoded payload, contains instructions aimed at Claude."""
    sample = skeleton(text[:MAX_LINE])
    rules = (OVERRIDE, ROLE_CHANGE, CONCEAL, EXFIL, NO_CONFIRM, MODEL_TOKENS, AUTHORITY)
    return any(rule.search(sample) for rule in rules)


def _html_comments(text: str):
    """Yield (offset, body) for each comment.

    A plain scan, because a regex turns quadratic on many unclosed comments. An
    unclosed comment runs to the end, as it does when Markdown is rendered.
    """
    start = text.find("<!--")
    while start >= 0:
        end = text.find("-->", start + 4)
        if end < 0:
            yield start, text[start + 4 :]
            return
        yield start, text[start + 4 : end]
        start = text.find("<!--", end + 3)


def _is_quoted(row: str, match: re.Match) -> bool:
    before = row[match.start() - 1] if match.start() else ""
    after = row[match.end()] if match.end() < len(row) else ""
    return (before != "" and before in QUOTES) or (after != "" and after in QUOTES)


def _emit(extension, rule, severity, title, detail, path, line, text) -> None:
    extension.finding(rule, "backdoor", severity, title, detail, path, line, clip(text))


def _invisible(extension: Extension, text: str, path: str, line: int, label: str) -> None:
    tags = [ch for ch in text if TAG_START <= ord(ch) <= TAG_END]
    if tags:
        hidden = "".join(chr(ord(ch) - TAG_START) for ch in tags if 0x20 <= ord(ch) - TAG_START < 0x7F)
        extension.finding(
            "instructions.invisible-text", "backdoor", Severity.CRITICAL,
            f"Invisible Unicode tag characters in {label}",
            "Tag characters do not display, but they can carry readable text to a model.",
            path, line, f"decoded: {clip(hidden)}",
        )
    found = sorted({INVISIBLE[ord(ch)] for ch in text if ord(ch) in INVISIBLE})
    if found:
        extension.finding(
            "instructions.invisible-text", "backdoor", Severity.HIGH,
            f"Invisible characters in {label}",
            f"Found {', '.join(found)}. These can hide text or make it read differently.",
            path, line,
        )


def _frontmatter(extension: Extension, doc: Doc) -> None:
    # An agent's "tools" field restricts it; only "allowed-tools" removes a prompt.
    tools = doc.frontmatter.get("allowed-tools")
    if tools:
        items = tools if isinstance(tools, list) else re.split(r",\s*|\s+(?=[A-Z])", tools)
        for item in (str(i).strip() for i in items):
            if item.lower() in BROAD_TOOLS:
                extension.finding(
                    "opsec.broad-allowed-tools", "opsec", Severity.HIGH,
                    f"{doc.kind.title()} pre-approves '{clip(item, 30)}'",
                    "Any command can run without a permission prompt while this is active.",
                    doc.path, 1, fix="List only the exact commands it needs.",
                )
            elif RISKY_TOOL.search(item):
                bundled = "${CLAUDE_PLUGIN_ROOT}" in item or "${CLAUDE_SKILL_DIR}" in item
                extension.finding(
                    "opsec.broad-allowed-tools", "opsec", Severity.LOW if bundled else Severity.MEDIUM,
                    f"{doc.kind.title()} pre-approves '{clip(item, 40)}'",
                    "This runs a script from the package with no prompt." if bundled else
                    "This command can reach the network or change files with no prompt.",
                    doc.path, 1, fix="Narrow the pattern to exact arguments.",
                )
    if str(doc.frontmatter.get("permissionMode", "")).lower() == "bypasspermissions":
        extension.finding(
            "opsec.bypass-permissions", "opsec", Severity.HIGH,
            f"{doc.kind.title()} asks to bypass permission prompts",
            "Every action would run without review.", doc.path, 1,
        )
    for comment in doc.frontmatter.get("_comments", []):
        if COMMENT_DIRECTIVE.search(comment):
            _emit(extension, "instructions.html-comment", Severity.MEDIUM,
                  f"Comment in the {doc.kind}'s header contains instructions",
                  "A reader skims past this, but Claude may still see it.", doc.path, 1, comment)
    hooks = doc.frontmatter.get("hooks")
    if hooks:
        for command in re.findall(r"command:\s*(.+)", str(hooks)):
            extension.capability(EXEC, REACH_HOOK, doc.path, 1, "hook in frontmatter")
            shell.scan_command(extension, command.strip("\"' "), doc.path, 1, REACH_HOOK)


def _embedded_commands(extension: Extension, doc: Doc) -> None:
    commands: list[tuple[str, int]] = []
    index = LineIndex(doc.text, doc.body_line)
    for pattern in (BANG_COMMAND, BANG_INLINE, BANG_BLOCK):
        for match in pattern.finditer(doc.text):
            commands.append((match.group(1), index.line(match.start())))
    for command, line in commands:
        extension.capability(EXEC, REACH_HOOK, doc.path, line, "runs when the skill loads")
        shell.scan_command(extension, command, doc.path, line, REACH_HOOK)
    if commands:
        extension.finding(
            "instructions.load-time-command", "opsec", Severity.LOW,
            f"{doc.kind.title()} runs a command as soon as it loads",
            f"{len(commands)} command(s) run before Claude reads the text, with no tool call to review.",
            doc.path, commands[0][1], clip(commands[0][0]),
        )
    for match in FENCED_SHELL.finditer(doc.text):
        for offset, row in enumerate(match.group(1).splitlines()):
            for rule in shell.RULES:
                if rule.rule in DANGEROUS_RULES and rule.pattern.search(row[:MAX_LINE]):
                    number = index.line(match.start()) + offset + 1
                    extension.finding(
                        rule.rule, rule.category, Severity.HIGH,
                        f"{doc.kind.title()} tells Claude to run: {rule.title.lower()}",
                        rule.detail, doc.path, number, clip(row),
                    )
