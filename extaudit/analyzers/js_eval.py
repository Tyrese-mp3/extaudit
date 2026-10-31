"""Work out constant values from JavaScript tokens without running them.

Covers the usual ways of hiding a string: concatenation, joins, reversed arrays,
String.fromCharCode, atob, Buffer and zlib. Anything else evaluates to None.
"""

from __future__ import annotations

import base64
import binascii
from typing import Callable
from urllib.parse import unquote

from .decoding import MAX_OUTPUT, inflate
from .js_tokens import Token

MAX_TOKENS = 4_000
MAX_STEPS = 20_000
MAX_TOTAL_STEPS = 3_000_000
MAX_DEPTH = 24
BAD_INPUT = (ValueError, TypeError, IndexError, OverflowError, LookupError, binascii.Error)
Value = str | bytes | int | list | None


def _b64(text: str) -> bytes:
    cleaned = text.strip()
    return base64.b64decode(cleaned + "=" * (-len(cleaned) % 4))


class Evaluator:
    def __init__(self, lookup: Callable[[str], list[Token] | None]):
        self.lookup = lookup
        self.steps = 0
        self.total = 0

    def evaluate(self, seq: list[Token]) -> Value:
        if not seq or len(seq) > MAX_TOKENS or self.total > MAX_TOTAL_STEPS:
            return None
        self.steps = 0
        try:
            return self._expression(seq, 0)
        except (RecursionError, *BAD_INPUT):
            return None

    def _charge(self, depth: int) -> bool:
        self.steps += 1
        self.total += 1
        return self.steps <= MAX_STEPS and depth <= MAX_DEPTH

    def _expression(self, seq: list[Token], depth: int) -> Value:
        if not self._charge(depth):
            return None
        pieces = _split(seq, "+")
        if len(pieces) == 1:
            return self._postfix(pieces[0], depth)
        total: Value = None
        for piece in pieces:
            value = self._postfix(piece, depth)
            if value is None or isinstance(value, (list, bytes)):
                return None
            total = str(value) if total is None else f"{total}{value}"
            if len(total) > MAX_OUTPUT:
                return None
        return total

    def _postfix(self, seq: list[Token], depth: int) -> Value:
        while seq and seq[0].kind == "id" and seq[0].value in {"await", "new"}:
            seq = seq[1:]
        if not seq:
            return None
        value, index = self._primary(seq, depth)
        while index > 0 and index < len(seq) and value is not None:
            if seq[index].value not in {".", "?."} or index + 1 >= len(seq):
                return None
            method = seq[index + 1].value
            index += 2
            if index >= len(seq) or seq[index].value != "(":
                return None
            end = _close(seq, index)
            if end < 0:
                return None
            args = [self._expression(a, depth + 1) for a in _split(seq[index + 1 : end], ",") if a]
            value = _method(value, method, args)
            index = end + 1
        return value if index > 0 else None

    def _primary(self, seq: list[Token], depth: int) -> tuple[Value, int]:
        token = seq[0]
        if token.kind == "str":
            return token.value, 1
        if token.kind == "tpl":
            return self._template(token, depth), 1
        if token.kind == "num":
            return int(token.value, 0), 1
        if token.value in {"(", "["}:
            end = _close(seq, 0)
            if end < 0:
                return None, -1
            if token.value == "(":
                return self._expression(seq[1:end], depth + 1), end + 1
            items = [self._expression(a, depth + 1) for a in _split(seq[1:end], ",") if a]
            return (None if any(i is None for i in items) else items), end + 1
        if token.kind == "id":
            return self._identifier(seq, depth)
        return None, -1

    def _identifier(self, seq: list[Token], depth: int) -> tuple[Value, int]:
        names = [seq[0].value]
        index = 1
        while index + 1 < len(seq) and seq[index].value == "." and seq[index + 1].kind == "id":
            if index + 2 >= len(seq) or seq[index + 2].value == "(" or len(names) >= 3:
                names.append(seq[index + 1].value)
                index += 2
                break
            names.append(seq[index + 1].value)
            index += 2
        name = ".".join(names)
        if index < len(seq) and seq[index].value == "(" and name in CALLS:
            end = _close(seq, index)
            if end < 0:
                return None, -1
            args = [self._expression(a, depth + 1) for a in _split(seq[index + 1 : end], ",") if a]
            return CALLS[name](args), end + 1
        if len(names) >= 2 and index < len(seq) and seq[index].value == "(":
            # value.method(...): evaluate the receiver and let _postfix apply the method.
            bound = self.lookup(names[0])
            if bound is None or len(names) != 2:
                return None, -1
            return self._expression(bound, depth + 1), 1
        bound = self.lookup(seq[0].value)
        return (self._expression(bound, depth + 1) if bound else None), 1

    def _template(self, token: Token, depth: int) -> Value:
        pieces = token.value.split("${}")
        if len(pieces) != len(token.parts) + 1:
            return None if token.parts else token.value
        out = [pieces[0]]
        for part, literal in zip(token.parts, pieces[1:]):
            value = self._expression(part, depth + 1)
            if value is None or isinstance(value, (list, bytes)):
                return None
            out.append(str(value))
            out.append(literal)
        return "".join(out)


def _split(seq: list[Token], separator: str) -> list[list[Token]]:
    parts: list[list[Token]] = []
    current: list[Token] = []
    level = 0
    for token in seq:
        if token.kind == "punct":
            if token.value in {"(", "[", "{"}:
                level += 1
            elif token.value in {")", "]", "}"}:
                level -= 1
            elif token.value == separator and level == 0:
                parts.append(current)
                current = []
                continue
        current.append(token)
    parts.append(current)
    return parts


def _close(seq: list[Token], start: int) -> int:
    level = 0
    for index in range(start, len(seq)):
        token = seq[index]
        if token.kind == "punct":
            if token.value in {"(", "[", "{"}:
                level += 1
            elif token.value in {")", "]", "}"}:
                level -= 1
                if level == 0:
                    return index
    return -1


def _from_char_code(args: list) -> Value:
    return "".join(chr(a) for a in args) if all(isinstance(a, int) for a in args) else None


def _buffer_from(args: list) -> Value:
    if not args:
        return None
    value = args[0]
    encoding = str(args[1]).lower() if len(args) > 1 and args[1] else "utf8"
    if isinstance(value, list) and all(isinstance(a, int) for a in value):
        return bytes(a & 255 for a in value)
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    if encoding in {"base64", "base64url"}:
        return _b64(value.replace("-", "+").replace("_", "/"))
    if encoding == "hex":
        return bytes.fromhex(value)
    return value.encode("utf-8", "replace")


def _atob(args: list) -> Value:
    return _b64(args[0]).decode("latin-1") if args and isinstance(args[0], str) else None


def _unquote(args: list) -> Value:
    return unquote(args[0]) if args and isinstance(args[0], str) else None


def _inflater(wbits: int) -> Callable[[list], Value]:
    def run(args: list) -> Value:
        return inflate(args[0], wbits) if args and isinstance(args[0], bytes) else None

    return run


CALLS: dict[str, Callable[[list], Value]] = {
    "String.fromCharCode": _from_char_code,
    "String.fromCodePoint": _from_char_code,
    "Buffer.from": _buffer_from,
    "atob": _atob,
    "decodeURIComponent": _unquote,
    "unescape": _unquote,
    "zlib.gunzipSync": _inflater(31),
    "zlib.inflateSync": _inflater(15),
    "zlib.inflateRawSync": _inflater(-15),
    "zlib.unzipSync": _inflater(47),
}


def _method(value: Value, method: str, args: list) -> Value:
    first = args[0] if args else None
    if isinstance(value, bytes):
        if method == "toString":
            encoding = str(first or "utf8").lower()
            if encoding == "hex":
                return value.hex()
            if encoding == "base64":
                return base64.b64encode(value).decode()
            return value.decode("utf-8", "replace")
        return None
    if isinstance(value, list):
        if method == "reverse":
            return list(reversed(value))
        if method == "join":
            return str("," if first is None else first).join(str(item) for item in value)
        if method == "concat" and isinstance(first, list):
            return value + first
        return None
    if isinstance(value, str):
        if method == "toString":
            return value
        if method == "split" and isinstance(first, str):
            return list(value) if first == "" else value.split(first)
        if method in {"replace", "replaceAll"} and len(args) >= 2 and all(isinstance(a, str) for a in args[:2]):
            return value.replace(args[0], args[1]) if method == "replaceAll" else value.replace(args[0], args[1], 1)
        if method in {"slice", "substring"} and all(isinstance(a, int) for a in args):
            return value[slice(*args[:2])]
        if method == "trim":
            return value.strip()
        if method == "toLowerCase":
            return value.lower()
        if method == "toUpperCase":
            return value.upper()
        if method == "concat" and all(isinstance(a, str) for a in args):
            return value + "".join(args)
        if method == "repeat" and isinstance(first, int) and len(value) * max(first, 0) <= MAX_OUTPUT:
            return value * first
    return None
