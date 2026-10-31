"""A small model of shell pipelines, so rules follow data instead of matching phrases.

Lists of patterns miss every new spelling of the same attack. This follows what the
attack has to do: get bytes from the network or a decoder into an interpreter. Data is
tracked through pipes, variables and files, in sh, batch and PowerShell.
"""

from __future__ import annotations

import re
from typing import Callable

DOWNLOAD = "download"
DECODED = "decoded"

INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "ash", "python", "python3", "node", "perl", "ruby", "php",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe", "iex",
    "invoke-expression", "eval", "source", ".",
}
WRAPPERS = {"sudo", "env", "nohup", "exec", "busybox", "command", "time", "nice", "call", "start"}
INLINE_FLAGS = {"-c", "/c", "/k", "-command", "-e", "--eval", "-lc", "-ic", "-ec"}
NET_WORD = re.compile(
    r"(?:^|[\s(`$|;&'\"])(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod|aria2c|"
    r"start-bitstransfer|scp|sftp)(?:\.exe)?(?=[\s'\")]|$)|downloadstring|downloadfile|net\.webclient",
    re.I,
)
DECODER = re.compile(
    r"\b(?:base64|base32|basenc)\b[^|]*\s(?:-d|-D|--decode)\b|\bxxd\b[^|]*\s-r|\bopenssl\b[^|]*\s-d\b|"
    r"\bprintf\b[^|]*\\[0-9x]|\becho\s+-e\b[^|]*\\[0-9x]|\buudecode\b|\bzcat\b|\bgunzip\b|"
    r"\bgzip\s+-d\b|\brev\b|\btr\s+\S+\s+\S+|frombase64string|\bcertutil\b[^|]*-decode",
    re.I,
)
SAVED_FILE = re.compile(
    r"""(?:DownloadFile\s*\([^,\n]{1,300},|urlretrieve\s*\([^,\n]{1,300},|\bscp\s+\S+)\s*['"]?([^\s'")]+)""", re.I
)
PROCESS_START = re.compile(r"^\s*(?:Start-Process|start|call|&)\s+[\"']?([^\s\"']+)", re.I)
ASSIGNMENT = re.compile(r"""^\s*(?:export\s+|set\s+|\$)?([A-Za-z_]\w*)\s*=\s*(.*)$""", re.S)
REDIRECT = re.compile(r"""(?<![0-9&])>>?\s*["']?([^\s;&|"']+)""")
OUTPUT_FLAG = re.compile(r"""\s(?:-o|-O|--output|--output-document|-OutFile)[= ]\s*["']?([^\s;&|"']+)""", re.I)
TEE = re.compile(r"""\btee\s+(?:-a\s+)?["']?([^\s;&|"']+)""", re.I)
VARIABLE = re.compile(r"\$\{?([A-Za-z_]\w*)\}?")
INLINE_DOWNLOAD_RUN = re.compile(
    r"(?:exec|eval)\s*\(.{0,160}(?:urlopen|requests\.get|urlretrieve|https?\.get|fetch\s*\()", re.I | re.S
)
MAX_TEXT = 200_000
MAX_STATEMENTS = 5_000
MAX_NESTING = 4

Report = Callable[[str, str, int, str], None]


def deobfuscate(line: str) -> str:
    """Undo tricks that split a word, such as cu''rl, c\\url, c^url or ${IFS}."""
    plain = line.replace("${IFS}", " ").replace("$IFS", " ")
    plain = re.sub(r"(?<=\w)(?:''|\"\")(?=\w)", "", plain)
    return re.sub(r"(?<=[A-Za-z])[\\^](?=[A-Za-z])", "", plain)


def split_statements(text: str) -> list[str]:
    """Split on ; && || and newlines, leaving quotes and brackets intact."""
    return _split(text, {";", "\n", "&&", "||", "&"})


def split_pipes(text: str) -> list[str]:
    return _split(text, {"|"})


def _split(text: str, separators: set[str]) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    quote = ""
    level = 0
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        if quote:
            if char == quote:
                quote = ""
            elif char == "\\" and quote == '"':
                current.append(char)
                index += 1
                char = text[index] if index < length else ""
        elif char in "\"'":
            quote = char
        elif char == "(":
            level += 1
        elif char == ")":
            level = max(level - 1, 0)
        elif level == 0:
            pair = text[index : index + 2]
            if pair in separators:
                parts.append("".join(current))
                current = []
                index += 2
                continue
            if pair in {"||", "&&"}:  # not a separator here, and not two single ones either
                current.append(pair)
                index += 2
                continue
            if char in separators and pair not in {"&>", ">&", "2>"} and text[index - 1:index] != ">":
                parts.append("".join(current))
                current = []
                index += 1
                continue
        current.append(char)
        index += 1
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _clean(word: str) -> str:
    return word.strip("\"'()`").removeprefix("./").replace("\\", "/")


def _base(word: str) -> str:
    return _clean(word).rsplit("/", 1)[-1].lower()


class ShellFlow:
    def __init__(self, report: Report):
        self.report = report
        self.tainted_variables: dict[str, str] = {}
        self.tainted_files: dict[str, str] = {}
        self.values: dict[str, str] = {}
        self.statements = 0

    def run(self, text: str) -> None:
        lines = text[:MAX_TEXT].splitlines()
        for number, line in enumerate(lines, 1):
            if line.lstrip().lower().startswith(("#", "rem ", "::")):
                continue
            self.line(deobfuscate(line), number, 0)

    def line(self, text: str, number: int, depth: int) -> None:
        for statement in split_statements(text):
            self.statements += 1
            if self.statements > MAX_STATEMENTS or depth > MAX_NESTING:
                return
            self.statement(self.substitute(statement), number, depth)

    def substitute(self, statement: str) -> str:
        if not self.values:
            return statement
        return VARIABLE.sub(lambda m: self.values.get(m.group(1), m.group(0)), statement)

    def statement(self, text: str, number: int, depth: int) -> None:
        assigned = ASSIGNMENT.match(text)
        if assigned and " " not in assigned.group(1) and not text.lstrip().startswith(("if", "for", "while")):
            self.assignment(assigned.group(1), assigned.group(2).strip(), number, depth)
            return
        if text.startswith(("$(", "`")):
            label = self.label_of(text)
            if label:
                self.fire(label, text, number, "Its output is run as a command")
            return
        label: str | None = None
        for stage in split_pipes(text):
            label = self.stage(stage, label, number, depth)

    def assignment(self, name: str, value: str, number: int, depth: int) -> None:
        label = self.label_of(value)
        if label:
            self.tainted_variables[name] = label
            return
        plain = value.strip("\"'")
        if plain and not re.search(r"[\s$(`]", plain):
            self.values[name] = plain

    def label_of(self, text: str) -> str | None:
        """Say whether text contains something fetched, decoded or derived from those."""
        if NET_WORD.search(text):
            return DOWNLOAD
        if DECODER.search(text):
            return DECODED
        for name in VARIABLE.findall(text):
            if name in self.tainted_variables:
                return self.tainted_variables[name]
        words = text.split()
        if words and _base(words[0]) in {"cat", "type", "get-content", "gc"}:
            for word in words[1:]:
                if _clean(word) in self.tainted_files:
                    return self.tainted_files[_clean(word)]
        return None

    def stage(self, stage: str, incoming: str | None, number: int, depth: int) -> str | None:
        started = PROCESS_START.match(stage)
        if started and _clean(started.group(1)) in self.tainted_files:
            self.fire(self.tainted_files[_clean(started.group(1))], stage, number, "The saved file is then run")
        for target in SAVED_FILE.findall(stage):
            self.tainted_files[_clean(target)] = DOWNLOAD
        words = stage.split()
        while words and _base(words[0]) in WRAPPERS:
            words = words[1:]
        if not words:
            return incoming
        program = _base(words[0])
        label = incoming or self.label_of(stage)
        cleaned = _clean(words[0])
        if cleaned in self.tainted_files:
            self.fire(self.tainted_files[cleaned], stage, number, "The saved file is then run")
        if program == "chmod":
            for word in words[1:]:
                if _clean(word) in self.tainted_files and "x" in words[1]:
                    self.fire(self.tainted_files[_clean(word)], stage, number, "The saved file is made executable")
        if program in INTERPRETERS:
            self.interpreter(program, words, stage, label, number, depth)
        if label:
            for pattern in (REDIRECT, OUTPUT_FLAG, TEE):
                for target in pattern.findall(stage):
                    self.tainted_files[_clean(target)] = label
        return label

    def interpreter(self, program: str, words: list[str], stage: str, label: str | None, number: int, depth: int) -> None:
        inline = self.inline_code(words, stage)
        if inline is not None:
            if INLINE_DOWNLOAD_RUN.search(inline):
                self.fire(DOWNLOAD, stage, number, "Inline code downloads and runs more code")
            for target in SAVED_FILE.findall(inline):
                self.tainted_files[_clean(target)] = DOWNLOAD
            for name in VARIABLE.findall(inline):
                if name in self.tainted_variables:
                    self.fire(self.tainted_variables[name], stage, number, "It goes straight into an interpreter")
                    return
            self.line(inline, number, depth + 1)
            return
        script = next((_clean(w) for w in words[1:] if not w.startswith(("-", "<")) and w != "/"), "")
        if script in self.tainted_files:
            self.fire(self.tainted_files[script], stage, number, "The saved file is then run")
        elif label and (not script or script == "-" or program in {"eval", "iex", "invoke-expression"} or script.startswith("$")):
            self.fire(label, stage, number, "It goes straight into an interpreter")

    def inline_code(self, words: list[str], stage: str) -> str | None:
        for index, word in enumerate(words[1:], 1):
            if word.lower() in INLINE_FLAGS and index + 1 < len(words):
                tail = stage.split(word, 1)[-1].strip()
                return tail.strip("\"'")
        return None

    def fire(self, label: str, text: str, number: int, how: str) -> None:
        if label == DOWNLOAD:
            self.report("backdoor.pipe-to-shell", f"Downloaded data is run. {how}", number, text)
        else:
            self.report("backdoor.decode-and-run", f"Decoded data is run. {how}", number, text)


def verdict(text: str) -> str | None:
    """Return a short description if the text would run fetched or decoded data."""
    found: list[str] = []
    ShellFlow(lambda rule, title, number, snippet: found.append(title)).run(text)
    return found[0] if found else None
