"""Shell and PowerShell checks, used for scripts, hook commands and skill commands."""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import (
    AGENT_CONFIG,
    EXEC,
    NET,
    PERSIST,
    REACH_CODE,
    SECRETS,
    Extension,
    Severity,
)
from ..patterns import AGENT_CONFIG_PATH, PERSISTENCE_PATH, SENSITIVE_PATH, clip, is_test_path
from .shell_flow import ShellFlow, deobfuscate

SUFFIXES = {".sh", ".bash", ".zsh", ".ps1", ".psm1", ".bat", ".cmd"}
MAX_LINE = 20_000

_DOWNLOAD = r"(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
_RUN = r"(?:sudo\s+)?(?:sh|bash|zsh|dash|python3?|node|perl|ruby|iex|Invoke-Expression)\b"
_SEP = r"(?:^|[\s;|&(`$])"

NETWORK = re.compile(
    _SEP + r"(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|rsync|ftp|Invoke-WebRequest|Invoke-RestMethod|"
    r"iwr|irm|Start-BitsTransfer|bitsadmin)(?=\s)",
    re.I,
)
WRITES_FILE = re.compile(r"(?:>>?\s*\S|\btee\b|\bsed\s+-i|Set-Content|Add-Content|Out-File|\bcp\b|\bmv\b)")


@dataclass(frozen=True)
class Rule:
    rule: str
    category: str
    severity: Severity
    title: str
    detail: str
    pattern: re.Pattern


_PIPE_DETAIL = "Whatever the server returns runs immediately, and it can change at any time."
_LOLBIN_DETAIL = "Windows ships this tool for other jobs. Attackers use it to fetch or run code quietly."

RULES = [
    Rule("backdoor.pipe-to-shell", "backdoor", Severity.CRITICAL,
         "Downloaded script is piped straight into a shell", _PIPE_DETAIL,
         re.compile(_SEP + _DOWNLOAD + r"[^\n|]{0,300}\|\s*" + _RUN, re.I)),
    Rule("backdoor.pipe-to-shell", "backdoor", Severity.CRITICAL,
         "Downloaded script is run through process substitution", _PIPE_DETAIL,
         re.compile(r"(?:\b(?:sh|bash|zsh|source)|(?:^|\s)\.)\s+<\(\s*(?:curl|wget)\b", re.I)),
    Rule("backdoor.pipe-to-shell", "backdoor", Severity.CRITICAL,
         "Downloaded text is run as a command", _PIPE_DETAIL,
         re.compile(r"""(?:\beval\s+|\b(?:sh|bash|zsh)\s+-c\s+)["']?\$\(\s*(?:curl|wget)\b""", re.I)),
    Rule("backdoor.pipe-to-shell", "backdoor", Severity.CRITICAL,
         "PowerShell runs downloaded text", _PIPE_DETAIL,
         re.compile(r"\b(?:iex|Invoke-Expression)\b[^\n]{0,80}(?:\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b|DownloadString|Net\.WebClient)", re.I)),
    Rule("backdoor.pipe-to-shell", "backdoor", Severity.CRITICAL,
         "PowerShell runs downloaded text", _PIPE_DETAIL,
         re.compile(r"DownloadString\([^\n]{0,200}\|\s*(?:iex|Invoke-Expression)\b", re.I)),
    Rule("backdoor.decode-and-run", "backdoor", Severity.CRITICAL,
         "Encoded text is decoded and run",
         "Encoding hides the real command from anyone reading the script.",
         re.compile(r"base64\s+(?:-d|-D|--decode)\b[^\n]{0,120}\|\s*" + _RUN, re.I)),
    Rule("backdoor.decode-and-run", "backdoor", Severity.CRITICAL,
         "Encoded text is decoded and run as a command",
         "Encoding hides the real command from anyone reading the script.",
         re.compile(r"\$\([^)\n]{0,200}base64\s+(?:-d|-D|--decode)\b[^)\n]{0,60}\)", re.I)),
    Rule("backdoor.decode-and-run", "backdoor", Severity.CRITICAL,
         "PowerShell runs an encoded command",
         "Encoding hides the real command from anyone reading the script.",
         re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-(?:e|enc|encodedcommand)\s", re.I)),
    Rule("backdoor.reverse-shell", "backdoor", Severity.CRITICAL,
         "Reverse shell pattern",
         "This hands a remote machine interactive control of the computer.",
         re.compile(r"/dev/tcp/|\bnc(?:at)?\s+[^\n]{0,60}-e\s|\bbash\s+-i\s+>&|mkfifo[^\n]{0,80}\bnc\b", re.I)),
    Rule("backdoor.lolbin", "backdoor", Severity.HIGH,
         "certutil is used to download or decode a file", _LOLBIN_DETAIL,
         re.compile(r"\bcertutil(?:\.exe)?\b[^\n]{0,120}-(?:urlcache|decode)\b", re.I)),
    Rule("backdoor.lolbin", "backdoor", Severity.HIGH,
         "bitsadmin is used to download a file", _LOLBIN_DETAIL,
         re.compile(r"\bbitsadmin(?:\.exe)?\b[^\n]{0,120}/transfer\b", re.I)),
    Rule("backdoor.lolbin", "backdoor", Severity.HIGH,
         "A Windows system tool loads code from a URL", _LOLBIN_DETAIL,
         re.compile(r"\b(?:mshta|rundll32|regsvr32|msiexec)(?:\.exe)?\b[^\n]{0,120}(?:https?:|javascript:)", re.I)),
    Rule("backdoor.env-exfil", "backdoor", Severity.HIGH,
         "Environment variables are sent over the network",
         "Environment variables usually hold API keys.",
         re.compile(r"\b(?:env|printenv|set)\b\s*\|\s*(?:curl|wget|nc)\b", re.I)),
    Rule("backdoor.file-upload", "backdoor", Severity.HIGH,
         "A local file is uploaded",
         "Check which file this sends and where it goes.",
         re.compile(r"\bcurl\b[^\n]{0,200}(?:--data(?:-binary|-raw)?\s+@|-d\s+@|-F\s+\S*=@|-T\s|--upload-file\b)", re.I)),
    Rule("backdoor.destructive", "backdoor", Severity.HIGH,
         "Command deletes a home or root folder",
         "This destroys data with no way to undo it.",
         re.compile(r"\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME)(?:\s|$|/\*)", re.I)),
    Rule("supply.remote-install", "backdoor", Severity.MEDIUM,
         "A package is installed straight from a URL",
         "It skips the registry, and the code at that address can change at any time.",
         re.compile(r"\b(?:npx|bunx|pnpm\s+dlx|uvx|pip3?\s+install|npm\s+(?:i|install)\b)[^\n]{0,120}https?://", re.I)),
    Rule("opsec.tls-disabled", "opsec", Severity.MEDIUM,
         "TLS certificate checks are turned off",
         "Traffic can be intercepted without any warning.",
         re.compile(r"\b(?:curl\b[^\n]{0,120}\s(?:-k|--insecure)\b|wget\b[^\n]{0,120}--no-check-certificate|http\.sslVerify\s+false|strict-ssl\s+false)", re.I)),
]

READS_STDIN = re.compile(r"\$\(\s*cat\s*\)|\bcat\s*(?:-\s*)?\||\bjq\b|\bread\s+-|\$\(</dev/stdin\)|\$input\b|\[Console\]::In", re.I)
EVAL_VARIABLE = re.compile(r"""(?:\beval\s+["']?\$|\b(?:sh|bash)\s+-c\s+["']?\$|\bInvoke-Expression\s+\$|\biex\s+\$)""", re.I)


def analyze(extension: Extension) -> None:
    for file in extension.files:
        if file.suffix not in SUFFIXES:
            continue
        test_file = is_test_path(file.path)
        text = file.text
        for number, line in enumerate(text.splitlines(), 1):
            scan_line(extension, line, file.path, number, reach=REACH_CODE, lowered=test_file)
        if not test_file:
            extension.capability(EXEC, REACH_CODE, file.path)
            trace_script(extension, text, file.path, 1)
            if READS_STDIN.search(text):
                for number, line in enumerate(text.splitlines(), 1):
                    if not _is_comment(line) and EVAL_VARIABLE.search(line[:MAX_LINE]):
                        extension.finding(
                            "input.script-runs-input", "input-validation", Severity.HIGH,
                            "Script reads input and runs a variable as a command",
                            "If this variable comes from stdin, anyone who controls that "
                            "input controls the command. Hook scripts get tool input on stdin.",
                            file.path, number, clip(line),
                            "Treat the input as data; never pass it to eval or sh -c.",
                        )


def scan_command(extension: Extension, command: str, origin: str, line: int, reach: str) -> None:
    """Scan a command stored in configuration, such as a hook or a skill."""
    for part in command.splitlines() or [command]:
        scan_line(extension, part, origin, line, reach)
    trace_script(extension, command, origin, line)


def trace_script(extension: Extension, text: str, path: str, first_line: int) -> None:
    """Follow fetched and decoded data through the script, across pipes, variables and files."""

    def report(rule: str, title: str, number: int, snippet: str) -> None:
        line = first_line + number - 1
        if not extension.already(rule, path, line):
            severity = Severity.CRITICAL
            extension.finding(rule, "backdoor", severity, title, _PIPE_DETAIL, path, line, clip(snippet))

    ShellFlow(report).run(text)


def scan_line(extension: Extension, line: str, path: str, number: int, reach: str, lowered: bool = False) -> None:
    line = line[:MAX_LINE]
    if _is_comment(line) or not line.strip():
        return
    plain = deobfuscate(line)
    variants = (line,) if plain == line else (line, plain)
    for rule in RULES:
        if any(rule.pattern.search(variant) for variant in variants):
            severity = rule.severity.lowered() if lowered else rule.severity
            extension.finding(rule.rule, rule.category, severity, rule.title, rule.detail, path, number, clip(line))
    if lowered:
        return
    if NETWORK.search(plain):
        extension.capability(NET, reach, path, number)
    if SENSITIVE_PATH.search(line):
        extension.capability(SECRETS, reach, path, number)
    if PERSISTENCE_PATH.search(line) and (WRITES_FILE.search(line) or re.search(r"\b(?:crontab|schtasks|launchctl|systemctl|Register-ScheduledTask|reg\s+add)\b", line, re.I)):
        extension.capability(PERSIST, reach, path, number)
        extension.finding("backdoor.persistence", "backdoor", Severity.HIGH,
                          "Script sets up something that survives a restart",
                          "An extension should not need to install itself into startup.",
                          path, number, clip(line))
    if AGENT_CONFIG_PATH.search(line) and WRITES_FILE.search(line):
        extension.capability(AGENT_CONFIG, reach, path, number)
        extension.finding("backdoor.agent-config-write", "backdoor", Severity.HIGH,
                          "Script changes Claude's own configuration",
                          "Changing settings can add hooks or turn off permission prompts.",
                          path, number, clip(line))


def _is_comment(line: str) -> bool:
    stripped = line.strip().lower()
    return stripped.startswith(("#", "rem ", "::"))
