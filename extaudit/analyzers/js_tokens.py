"""A small JavaScript and TypeScript tokenizer.

It separates code from strings, comments, regular expressions and template
literals, which is the part plain text search gets wrong. Bracket matching on
the resulting tokens gives the analyzer enough structure to find functions and
call arguments.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PUNCT3 = {"===", "!==", "...", "**=", "<<=", ">>=", "&&=", "||=", "??=", ">>>"}
PUNCT2 = {
    "=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=",
    "%=", "&=", "|=", "^=", "<<", ">>", "**",
}
REGEX_AFTER_WORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case",
    "do", "else", "yield", "await",
}
MAX_TEMPLATE_DEPTH = 32
MIN_ESCAPES = 3
HEX_DIGITS = set("0123456789abcdefABCDEF")
SIMPLE_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
MAX_REGEX = 512
# Possessive quantifiers: a failed match gives up at once instead of backtracking.
REGEX_LITERAL = re.compile(r"/(?:[^/\\\[\n]++|\\[^\n]|\[(?:[^\]\\\n]++|\\[^\n])*+\])*+/[A-Za-z]*")


@dataclass(slots=True)
class Token:
    kind: str  # id | str | tpl | num | regex | punct
    value: str
    line: int
    parts: list[list["Token"]] = field(default_factory=list)  # expressions inside a template
    escaped: bool = False  # a string written as \x or \u escapes rather than plain text


def tokenize(source: str, line: int = 1, depth: int = 0) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    length = len(source)
    if source.startswith("#!"):
        index = source.find("\n")
        index = length if index < 0 else index
    while index < length:
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
        elif char in " \t\r\f\v﻿":
            index += 1
        elif char == "/" and source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end < 0 else end
        elif char == "/" and source.startswith("/*", index):
            end = source.find("*/", index + 2)
            stop = length if end < 0 else end + 2
            line += source.count("\n", index, stop)
            index = stop
        elif char in "\"'":
            value, stop, escapes = _read_string(source, index)
            tokens.append(Token("str", value, line, escaped=escapes >= MIN_ESCAPES))
            index = stop
        elif char == "`":
            token, stop, lines = _read_template(source, index, line, depth)
            tokens.append(token)
            line += lines
            index = stop
        elif char == "/" and _regex_allowed(tokens):
            stop = _read_regex(source, index)
            if stop < 0:
                tokens.append(Token("punct", char, line))
                index += 1
            else:
                tokens.append(Token("regex", source[index:stop], line))
                index = stop
        elif char.isdigit():
            stop = index + 1
            while stop < length and (source[stop].isalnum() or source[stop] in "._"):
                stop += 1
            tokens.append(Token("num", source[index:stop], line))
            index = stop
        elif char.isalpha() or char in "_$" or ord(char) > 127:
            stop = index + 1
            while stop < length and (source[stop].isalnum() or source[stop] in "_$" or ord(source[stop]) > 127):
                stop += 1
            tokens.append(Token("id", source[index:stop], line))
            index = stop
        else:
            for size, table in ((3, PUNCT3), (2, PUNCT2)):
                if source[index : index + size] in table:
                    tokens.append(Token("punct", source[index : index + size], line))
                    index += size
                    break
            else:
                tokens.append(Token("punct", char, line))
                index += 1
    return tokens


def _read_string(source: str, start: int) -> tuple[str, int, int]:
    """Return the decoded value, where the string ends, and how many \\x or \\u escapes it used."""
    quote = source[start]
    index = start + 1
    length = len(source)
    out: list[str] = []
    escapes = 0
    while index < length:
        char = source[index]
        if char == "\\" and index + 1 < length:
            following = source[index + 1]
            width = {"x": 2, "u": 4}.get(following, 0)
            digits = source[index + 2 : index + 2 + width]
            if width and len(digits) == width and all(c in HEX_DIGITS for c in digits):
                out.append(chr(int(digits, 16)))
                escapes += 1
                index += 2 + width
            else:
                out.append(SIMPLE_ESCAPES.get(following, following))
                index += 2
        elif char == quote:
            return "".join(out), index + 1, escapes
        elif char == "\n":
            return "".join(out), index, escapes  # unterminated, as apostrophes in JSX text can be
        else:
            out.append(char)
            index += 1
    return "".join(out), index, escapes


def _read_template(source: str, start: int, line: int, depth: int) -> tuple[Token, int, int]:
    index = start + 1
    length = len(source)
    text: list[str] = []
    parts: list[list[Token]] = []
    newlines = 0
    while index < length:
        char = source[index]
        if char == "\\" and index + 1 < length:
            text.append(source[index + 1])
            newlines += source[index + 1] == "\n"
            index += 2
        elif char == "`":
            index += 1
            break
        elif char == "$" and source.startswith("${", index):
            stop = _template_expression_end(source, index + 2)
            if depth < MAX_TEMPLATE_DEPTH:
                parts.append(tokenize(source[index + 2 : stop], line + newlines, depth + 1))
            newlines += source.count("\n", index, stop)
            text.append("${}")
            index = stop + 1
        else:
            newlines += char == "\n"
            text.append(char)
            index += 1
    return Token("tpl", "".join(text), line, parts), index, newlines


def _template_expression_end(source: str, start: int) -> int:
    index = start
    depth = 1
    length = len(source)
    while index < length:
        char = source[index]
        if char in "\"'":
            _, index, _ = _read_string(source, index)
            continue
        if char == "`":
            index = _skip_template(source, index)
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return length


def _skip_template(source: str, start: int) -> int:
    index = start + 1
    length = len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            index += 2
        elif char == "`":
            return index + 1
        elif char == "$" and source.startswith("${", index):
            index = _template_expression_end(source, index + 2) + 1
        else:
            index += 1
    return length


def _regex_allowed(tokens: list[Token]) -> bool:
    if not tokens:
        return True
    last = tokens[-1]
    if last.kind in {"str", "tpl", "num", "regex"}:
        return False
    if last.kind == "id":
        return last.value in REGEX_AFTER_WORDS
    return last.value not in {")", "]", "}"}


def _read_regex(source: str, start: int) -> int:
    # The window keeps a line full of unclosed slashes from going quadratic.
    match = REGEX_LITERAL.match(source, start, start + MAX_REGEX)
    return match.end() if match else -1


def match_brackets(tokens: list[Token]) -> dict[int, int]:
    """Map each opening bracket's index to its closing bracket's index."""
    pairs: dict[int, int] = {}
    stack: list[tuple[str, int]] = []
    closers = {")": "(", "]": "[", "}": "{"}
    for index, token in enumerate(tokens):
        if token.kind != "punct":
            continue
        if token.value in "([{" and len(token.value) == 1:
            stack.append((token.value, index))
        elif token.value in closers:
            while stack:
                opener, position = stack.pop()
                if opener == closers[token.value]:
                    pairs[position] = index
                    break
    return pairs
