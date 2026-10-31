"""Bounded decoding helpers. Decompression is capped so a payload cannot act as a bomb."""

from __future__ import annotations

import base64
import binascii
import bz2
import lzma
import zlib

MAX_OUTPUT = 1_000_000


def inflate(data: bytes, wbits: int = 15) -> bytes | None:
    try:
        return zlib.decompressobj(wbits).decompress(data, MAX_OUTPUT)
    except zlib.error:
        return None


def unbzip(data: bytes) -> bytes | None:
    try:
        return bz2.BZ2Decompressor().decompress(data, MAX_OUTPUT)
    except (OSError, EOFError, ValueError):
        return None


def unxz(data: bytes) -> bytes | None:
    try:
        return lzma.LZMADecompressor().decompress(data, MAX_OUTPUT)
    except (lzma.LZMAError, EOFError, ValueError):
        return None


def unpack(data: bytes) -> bytes:
    """Remove a compression layer if the data starts with a known signature."""
    result: bytes | None = None
    if data[:2] == b"\x1f\x8b":
        result = inflate(data, 31)
    elif data[:1] == b"\x78":
        result = inflate(data)
    elif data[:3] == b"BZh":
        result = unbzip(data)
    elif data[:6] == b"\xfd7zXZ\x00":
        result = unxz(data)
    return result if result is not None else data


def base64_bytes(token: str) -> bytes | None:
    try:
        return base64.b64decode(token + "=" * (-len(token) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def hex_bytes(token: str) -> bytes | None:
    try:
        return bytes.fromhex(token)
    except ValueError:
        return None


def readable(data: bytes) -> str | None:
    """Return text when the bytes look like something a person or interpreter would read."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    good = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if good / len(text) >= 0.95 else None
