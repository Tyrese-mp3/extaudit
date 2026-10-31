"""Work out constant values in Python source without running it.

A small evaluator for the expressions people use to hide strings: concatenation,
joins, reversed slices, chr() and decoders such as base64 and zlib. It reads the
tree and computes on plain values, so nothing in the target ever executes. Anything
it does not recognize evaluates to None.
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
from typing import Callable

from .decoding import MAX_OUTPUT, inflate, unbzip, unxz

MAX_STEPS = 20_000
MAX_TOTAL_STEPS = 3_000_000
MAX_DEPTH = 30
Value = str | bytes | int | list | None


def _data(value: Value) -> bytes | None:
    if isinstance(value, bytes):
        return value
    return value.encode("utf-8", "replace") if isinstance(value, str) else None


def _b64(value: bytes) -> bytes:
    return base64.b64decode(value + b"=" * (-len(value) % 4))


DECODERS: dict[str, Callable[[bytes], bytes | None]] = {
    "base64.b64decode": _b64,
    "base64.urlsafe_b64decode": lambda v: base64.urlsafe_b64decode(v + b"=" * (-len(v) % 4)),
    "base64.decodebytes": _b64,
    "base64.b32decode": base64.b32decode,
    "base64.b85decode": base64.b85decode,
    "base64.a85decode": base64.a85decode,
    "binascii.a2b_base64": _b64,
    "binascii.unhexlify": binascii.unhexlify,
    "binascii.a2b_hex": binascii.unhexlify,
    "bytes.fromhex": lambda v: bytes.fromhex(v.decode("ascii", "replace")),
    "zlib.decompress": inflate,
    "gzip.decompress": lambda v: inflate(v, 31),
    "bz2.decompress": unbzip,
    "lzma.decompress": unxz,
}
TEXT_METHODS: dict[str, Callable] = {
    "strip": str.strip,
    "lstrip": str.lstrip,
    "rstrip": str.rstrip,
    "lower": str.lower,
    "upper": str.upper,
    "swapcase": str.swapcase,
}
BAD_INPUT = (ValueError, TypeError, IndexError, OverflowError, LookupError, UnicodeError, binascii.Error)


class Evaluator:
    def __init__(self, resolve: Callable[[ast.AST], str], bindings: dict[str, ast.expr]):
        self.resolve = resolve
        self.bindings = bindings
        self.steps = 0
        self.total = 0

    def evaluate(self, node: ast.AST | None) -> Value:
        if node is None or self.total > MAX_TOTAL_STEPS:
            return None
        self.steps = 0
        try:
            return self._value(node, {}, 0)
        except (RecursionError, *BAD_INPUT):
            return None

    def _value(self, node: ast.AST, env: dict, depth: int) -> Value:
        self.steps += 1
        self.total += 1
        if self.steps > MAX_STEPS or depth > MAX_DEPTH:
            return None
        if isinstance(node, ast.Constant):
            value = node.value
            return value if isinstance(value, (str, bytes, int)) and not isinstance(value, bool) else None
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            bound = self.bindings.get(node.id)
            return self._value(bound, env, depth + 1) if bound is not None else None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            value = self._value(node.operand, env, depth + 1)
            return -value if isinstance(value, int) else None
        if isinstance(node, (ast.List, ast.Tuple)):
            items = [self._value(item, env, depth + 1) for item in node.elts]
            return None if any(item is None for item in items) else items
        if isinstance(node, ast.JoinedStr):
            return self._fstring(node, env, depth)
        if isinstance(node, ast.BinOp):
            return self._binary(node, env, depth)
        if isinstance(node, ast.Subscript):
            return self._subscript(node, env, depth)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp)):
            return self._comprehension(node, env, depth)
        if isinstance(node, ast.Call):
            return self._call(node, env, depth)
        return None

    def _fstring(self, node: ast.JoinedStr, env: dict, depth: int) -> Value:
        parts: list[str] = []
        for piece in node.values:
            inner = piece.value if isinstance(piece, ast.FormattedValue) else piece
            value = self._value(inner, env, depth + 1)
            if value is None:
                return None
            parts.append(value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value))
        return "".join(parts)

    def _binary(self, node: ast.BinOp, env: dict, depth: int) -> Value:
        left = self._value(node.left, env, depth + 1)
        right = self._value(node.right, env, depth + 1)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add) and type(left) is type(right):
            if isinstance(left, (str, bytes)) and len(left) + len(right) > MAX_OUTPUT:
                return None
            return left + right
        if isinstance(node.op, ast.Mult) and isinstance(left, (str, bytes)) and isinstance(right, int):
            return left * right if len(left) * max(right, 0) <= MAX_OUTPUT else None
        if isinstance(node.op, ast.Mod) and isinstance(left, str):
            return left % (tuple(right) if isinstance(right, list) else right)
        if isinstance(left, int) and isinstance(right, int) and isinstance(node.op, (ast.Add, ast.Sub, ast.BitXor)):
            return {ast.Add: left + right, ast.Sub: left - right, ast.BitXor: left ^ right}[type(node.op)]
        return None

    def _subscript(self, node: ast.Subscript, env: dict, depth: int) -> Value:
        base = self._value(node.value, env, depth + 1)
        if base is None or isinstance(base, int):
            return None
        index = node.slice
        if isinstance(index, ast.Slice):
            bounds = [self._value(p, env, depth + 1) if p is not None else None for p in (index.lower, index.upper, index.step)]
            return base[slice(*bounds)]
        position = self._value(index, env, depth + 1)
        return base[position] if isinstance(position, int) else None

    def _comprehension(self, node, env: dict, depth: int) -> Value:
        if len(node.generators) != 1 or node.generators[0].ifs:
            return None
        generator = node.generators[0]
        source = self._value(generator.iter, env, depth + 1)
        if not isinstance(generator.target, ast.Name) or not isinstance(source, (str, bytes, list)):
            return None
        out = []
        for item in source:
            value = self._value(node.elt, {**env, generator.target.id: item}, depth + 1)
            if value is None:
                return None
            out.append(value)
        return out

    def _call(self, node: ast.Call, env: dict, depth: int) -> Value:
        name = self.resolve(node.func)
        args = [self._value(arg, env, depth + 1) for arg in node.args]
        first = args[0] if args else None
        if name in DECODERS:
            data = _data(first)
            return DECODERS[name](data) if data is not None else None
        if name == "codecs.decode":
            return self._codecs(first, args[1] if len(args) > 1 else None)
        if name == "chr" and isinstance(first, int):
            return chr(first)
        if name == "ord" and isinstance(first, str) and len(first) == 1:
            return ord(first)
        if name == "str" and first is not None:
            return first.decode("utf-8", "replace") if isinstance(first, bytes) else str(first)
        if name in {"bytes", "bytearray"}:
            if isinstance(first, list):
                return bytes(first)
            return first if isinstance(first, bytes) else None
        if name in {"reversed", "list"} and isinstance(first, (str, list, bytes)):
            return list(reversed(first)) if name == "reversed" else list(first)
        if isinstance(node.func, ast.Attribute):
            receiver = self._value(node.func.value, env, depth + 1)
            if receiver is not None:
                return self._method(receiver, node.func.attr, args)
        return None

    def _codecs(self, value: Value, encoding: Value) -> Value:
        label = str(encoding or "utf-8").lower().replace("-", "_")
        if label in {"rot13", "rot_13"} and isinstance(value, str):
            return codecs.decode(value, "rot13")
        data = _data(value)
        if data is None:
            return None
        if label in {"hex", "hex_codec"}:
            return binascii.unhexlify(data)
        if label in {"base64", "base64_codec"}:
            return _b64(data)
        if label in {"zlib", "zlib_codec"}:
            return inflate(data)
        return data.decode(label, "replace")

    def _method(self, receiver: Value, method: str, args: list) -> Value:
        if method == "decode" and isinstance(receiver, bytes):
            encoding = args[0] if args and isinstance(args[0], str) else "utf-8"
            return receiver.decode(encoding, "replace")
        if method == "encode" and isinstance(receiver, str):
            return receiver.encode("utf-8", "replace")
        if method == "join" and isinstance(receiver, (str, bytes)) and args and isinstance(args[0], list):
            return receiver.join(args[0])
        if isinstance(receiver, str):
            if method in TEXT_METHODS:
                return TEXT_METHODS[method](receiver)
            if method == "replace" and len(args) >= 2 and all(isinstance(a, str) for a in args[:2]):
                return receiver.replace(args[0], args[1])
            if method == "format" and all(isinstance(a, (str, int)) for a in args):
                return receiver.format(*args)
        return None
