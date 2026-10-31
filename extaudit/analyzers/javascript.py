"""JavaScript and TypeScript analysis on a token stream.

The standard library has no JS parser, so this works from tokens and bracket
matching. It tracks variables by name without modelling scope, which makes it
lean toward reporting too much rather than too little.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

from ..model import (
    DYNAMIC,
    EXEC,
    FS_READ,
    FS_WRITE,
    NET,
    REACH_CODE,
    REACH_TOOL,
    SECRETS,
    UNTRUSTED,
    Extension,
    PackageFile,
    Severity,
)
from ..patterns import CREDENTIAL_FILE, SENSITIVE_PATH, clip, entropy, is_secret_name, is_test_path
from . import shell
from .js_eval import Evaluator
from .js_tokens import Token, match_brackets, tokenize

SUFFIXES = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"}
MAX_TOKENIZE_BYTES = 3 * 1024 * 1024
MAX_LINE = 20_000
MAX_DEPTH = 4
MAX_WORK = 6_000_000

SHELL_CALLS = {"child_process.exec", "child_process.execSync", "shelljs.exec"}
SPAWN_CALLS = {
    "child_process.spawn", "child_process.spawnSync", "child_process.execFile",
    "child_process.execFileSync", "child_process.fork", "Bun.spawn", "Bun.spawnSync",
    "execa", "execa.execa", "execa.execaSync", "execa.command", "Deno.Command", "Deno.run",
}
COMMAND_CALLS = SHELL_CALLS | SPAWN_CALLS
CODE_CALLS = {
    "eval", "Function", "vm.runInThisContext", "vm.runInNewContext", "vm.runInContext",
    "vm.Script", "vm.compileFunction",
}
MODULE_LOADERS = {"require", "import"}
READ_CALLS = {
    "fs.readFile", "fs.readFileSync", "fs.createReadStream", "fs.readdir", "fs.readdirSync",
    "fs.opendir", "Bun.file",
}
WRITE_CALLS = {
    f"fs.{name}{suffix}"
    for name in ("writeFile", "appendFile", "unlink", "rm", "rmdir", "rename", "copyFile", "cp",
                 "mkdir", "chmod", "symlink", "truncate")
    for suffix in ("", "Sync")
} | {"fs.createWriteStream", "Bun.write"}
COPY_CALLS = {f"fs.{name}{suffix}" for name in ("copyFile", "cp", "rename") for suffix in ("", "Sync")}
AWAIT_PASS_THROUGH = {"realpath", "resolve", "normalize", "parse", "parseAsync", "safeParse", "safeParseAsync", "validate"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "request"}
NET_CALLS = {
    "fetch", "node-fetch", "undici.fetch", "undici.request", "axios", "got", "ky", "superagent",
    "http.request", "http.get", "https.request", "https.get", "net.connect",
    "net.createConnection", "tls.connect", "dgram.createSocket", "WebSocket",
} | {f"{lib}.{verb}" for lib in ("axios", "got", "ky", "superagent") for verb in HTTP_VERBS}
TEMPLATE_CALLS = {
    "ejs.render", "ejs.compile", "pug.render", "pug.compile", "handlebars.compile",
    "Handlebars.compile", "nunjucks.renderString", "lodash.template", "underscore.template",
}
DESERIALIZE_CALLS = {"node-serialize.unserialize", "v8.deserialize"}
SQL_METHODS = {"query", "execute", "exec", "all", "get", "run", "prepare", "raw", "$queryRawUnsafe", "$executeRawUnsafe"}
SQL_RECEIVER = re.compile(r"(?i)(?:^db$|database|conn|pool|sql|knex|prisma|client)")
SANITIZERS = {
    "Number", "parseInt", "parseFloat", "Boolean", "isNaN", "basename", "path.basename",
    "encodeURIComponent", "shellEscape", "escapeShellArg", "shellQuote.quote", "Math.floor",
    "Math.ceil", "Math.round", "Math.min", "Math.max",
}
SAFE_ZOD = {"number", "boolean", "enum", "literal", "nativeEnum", "int", "date"}
CHECKED_ZOD = {"regex", "uuid", "cuid", "ulid", "ip", "email", "datetime"}
CLEAN_PROPERTIES = {"length", "size"}
GUARD_METHODS = {"startsWith", "test", "match", "includes", "has"}
KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "function", "typeof", "await", "new",
    "yield", "delete", "void", "throw", "case", "class", "super",
}
LOG_METHODS = {"log", "info", "warn", "error", "debug", "trace"}
METHOD_PREFIX = {"{", "}", ";", ",", "async", "static", "public", "private", "protected", "override", "get", "set", "*"}
HIGHER_ORDER = {"forEach", "map", "flatMap", "filter", "some", "every", "find", "then", "catch", "finally", "on", "once"}
MUTATORS = {"push", "unshift", "add", "set"}
DNS_CALLS = {"dns.resolve", "dns.resolve4", "dns.resolve6", "dns.resolveTxt", "dns.lookup"}
MAX_APPENDS = 5_000
GLOBAL_SINKS = {"eval", "Function", "fetch", "Bun", "Deno", "WebSocket"}
GLOBAL_PREFIXES = ("globalThis.", "global.", "window.")
INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "python", "python3", "python.exe", "node", "node.exe", "perl", "ruby", "php",
}
INLINE_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-e", "--eval", "-lc", "-ic", "-ec"}
DISGUISE_NAMES = {"atob", "fromCharCode", "fromCodePoint", "Buffer", "reverse", "unescape", "gunzipSync", "inflateSync"}

CREDENTIALS = "credential files"
ENVIRONMENT = "all environment variables"
DOWNLOAD = "downloaded content"
SECRET_VARIABLE = "a secret environment variable"
STANDARD_INPUT = "standard input"
EXFIL_DETAIL = {
    CREDENTIALS: "Data read from a credential file reaches a network call.",
    ENVIRONMENT: "The whole environment, which usually holds API keys, reaches a network call.",
    SECRET_VARIABLE: "A key is sent in the body of a request. Sending it in a header to its own service is normal; this is not.",
    STANDARD_INPUT: "Hook scripts get prompts and tool data on standard input, and this sends it out.",
}
EXFIL_SEVERITY = {
    CREDENTIALS: Severity.CRITICAL,
    ENVIRONMENT: Severity.CRITICAL,
    SECRET_VARIABLE: Severity.MEDIUM,
    STANDARD_INPUT: Severity.MEDIUM,
}
SIGNED_REQUEST_FIELDS = {"headers", "auth", "agent", "signal", "timeout"}
DOWNLOADERS = {"fetch", "axios", "got"}

TLS_OFF = re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED")
BIND_ALL = re.compile(r"""\.listen\([^)\n]{0,80}["']0\.0\.0\.0["']|\bhost(?:name)?\s*:\s*["']0\.0\.0\.0["']""")
CORS_ANY = re.compile(
    r"""Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["']|cors\(\s*\{\s*origin\s*:\s*(?:["']\*["']|true)"""
)
ENV_DUMP = re.compile(r"JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:entries|keys|values)\(\s*process\.env\s*\)")
DECODE_EVAL = re.compile(
    r"\b(?:eval|Function|execSync|exec)\s*\(\s*(?:await\s+)?(?:atob|Buffer\.from|unescape|decodeURIComponent|String\.fromCharCode)\b"
)
OBFUSCATOR_NAME = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
MCP_IMPORT = re.compile(r"modelcontextprotocol|fastmcp|mcp-framework|claude-agent-sdk")
NOT_LOCAL = object()


@dataclass
class Fn:
    params: list[list[str]]
    start: int
    end: int
    line: int = 0
    expression: bool = False
    name: str = ""


@dataclass
class State:
    tainted: dict[str, str]
    validated: set[str] = field(default_factory=set)
    safe: set[str] = field(default_factory=set)
    instances: dict[str, str] = field(default_factory=dict)
    via: tuple[str, ...] = ()
    returned: str | None = None


@dataclass
class Summary:
    """What a helper does with its input, so callers need not guess."""

    returned: str | None
    validated: set[str]


def analyze(extension: Extension) -> None:
    project = Project(extension)
    for file in extension.files:
        if file.suffix not in SUFFIXES or is_test_path(file.path):
            continue
        if file.suffix in {".js", ".mjs", ".cjs"} and _is_minified(file.text):
            extension.gap(file.path, "code is minified or bundled, so tracing is less reliable")
        if len(file.data) > MAX_TOKENIZE_BYTES:
            extension.gap(file.path, "file is too large to tokenize; only text patterns were checked")
            _text_checks(file, extension, [])
            continue
        try:
            unit = Unit(file)
        except (RecursionError, MemoryError):
            extension.gap(file.path, "code is nested too deeply to tokenize")
            continue
        project.units.append(unit)
    for unit in project.units:
        unit.declare_tools(extension)
        _file_pass(unit, extension)
    try:
        for unit in project.units:
            try:
                BehaviorFlow(project, "").run(unit)
            except RecursionError:
                extension.gap(unit.file.path, "code is nested too deeply to trace")
    except TooComplex:
        extension.gap("behavior tracing", "code is too complex to trace fully; some files were not followed")
    project.work = 0  # tool tracing gets its own budget
    try:
        for unit in project.units:
            for tool, fn, safe, checked in unit.registrations(project):
                flow = Flow(project, tool)
                state = State({n: n for n in (fn.params[0] if fn.params else []) if n not in safe}, set(checked), safe)
                try:
                    flow.enter(unit, fn, state, 0)
                except RecursionError:
                    extension.gap(f"{unit.file.path}:{fn.line}", "code is nested too deeply to trace")
    except TooComplex:
        extension.gap("tool tracing", "code is too complex to trace fully; some tools were not followed")


def _is_minified(text: str) -> bool:
    return len(text) > 20_000 and len(text) / max(text.count("\n"), 1) > 300


class TooComplex(Exception):
    """The work budget ran out, so crafted code cannot stall the scan."""


class Project:
    def __init__(self, extension: Extension):
        self.extension = extension
        self.units: list[Unit] = []
        self.work = 0

    def charge(self, amount: int) -> None:
        self.work += amount
        if self.work > MAX_WORK:
            raise TooComplex

    def find(self, name: str, near: "Unit") -> tuple["Unit", Fn] | None:
        if name in near.functions:
            return near, near.functions[name]
        matches = [u for u in self.units if name in u.functions]
        return (matches[0], matches[0].functions[name]) if len(matches) == 1 else None


class Unit:
    """One tokenized source file."""

    def __init__(self, file: PackageFile):
        self.file = file
        self.lines = file.text.splitlines()
        self.toks: list[Token] = tokenize(file.text)
        self.count = len(self.toks)
        end = self.toks[-1].line if self.toks else 1
        self.toks += [Token("eof", "", end) for _ in range(5)]
        self.match = match_brackets(self.toks)
        self.reverse = {close: start for start, close in self.match.items()}
        self.aliases: dict[str, str] = {}
        self.modules: set[str] = set()
        self.functions: dict[str, Fn] = {}
        self.constants: dict[str, tuple[int, int]] = {}
        self.appends: dict[str, list[tuple[int, int]]] = {}
        self.computed_modules: set[str] = set()
        self.parents: dict[str, str] = {}
        self.class_starts: list[int] = []
        self.class_spans: list[tuple[int, int, str]] = []
        self.evaluator = Evaluator(self._constant_tokens)
        self._scan_constants()
        self._scan_imports()
        self._scan_classes()
        self._scan_functions()
        self._scan_aliases()
        self._scan_aliases()  # a second pass catches aliases of aliases
        self.imports_mcp = any(MCP_IMPORT.search(m) for m in self.modules) or "CallToolRequestSchema" in file.text

    def snippet(self, line: int) -> str:
        return clip(self.lines[line - 1]) if 0 < line <= len(self.lines) else ""

    def evaluate(self, a: int, b: int):
        return self.evaluator.evaluate(self.toks[a:b])

    def _constant_tokens(self, name: str) -> list[Token] | None:
        span = self.constants.get(name)
        return self.toks[span[0] : span[1]] if span else None

    def _scan_constants(self) -> None:
        t = self.toks
        for i in range(self.count):
            if t[i].kind != "id":
                continue
            if t[i].value in {"const", "let", "var"}:
                if t[i + 1].kind == "id" and t[i + 2].value == "=":
                    self.constants[t[i + 1].value] = (i + 3, self.expr_end(i + 3, self.count))
            elif t[i + 1].value == "+=" and len(self.appends) < MAX_APPENDS:
                self.appends.setdefault(t[i].value, []).append((i + 2, self.expr_end(i + 2, self.count)))

    def _scan_imports(self) -> None:
        t = self.toks
        for i in range(self.count):
            token = t[i]
            if token.kind != "id":
                continue
            if token.value == "import" and t[i - 1].value != ".":
                if t[i + 1].value == "(":
                    self._dynamic_module(i)
                else:
                    self._static_import(i)
            elif token.value == "require" and t[i + 1].value == "(":
                self._dynamic_module(i)
            elif token.value == "promisify" and t[i + 1].value == "(":
                self._bind_promisify(i)

    def _dynamic_module(self, i: int) -> None:
        close = self.match.get(i + 1)
        if close is None:
            return
        name = self.evaluate(i + 2, close)
        if isinstance(name, str):
            if close != i + 3 or self.toks[i + 2].escaped:
                self.computed_modules.add(_normalize(name))
            self._bind_module(i, name, close)

    def _static_import(self, i: int) -> None:
        t = self.toks
        if t[i + 1].value == "type":
            return
        j = i + 1
        limit = min(i + 300, self.count)
        while j < limit and t[j].kind != "str":
            j += 1
        if j >= limit:
            return
        module = _normalize(t[j].value)
        self.modules.add(module)
        k = i + 1
        while k < j:
            token = t[k]
            if token.value == "*" and t[k + 1].value == "as":
                self.aliases[t[k + 2].value] = module
                k += 3
            elif token.value == "{":
                close = self.match.get(k, j)
                m = k + 1
                while m < close:
                    if t[m].kind == "id" and t[m].value != "type":
                        local = t[m + 2].value if t[m + 1].value == "as" else t[m].value
                        self.aliases[local] = f"{module}.{t[m].value}"
                        m += 3 if t[m + 1].value == "as" else 1
                    else:
                        m += 1
                k = close + 1
            elif token.kind == "id" and token.value != "from":
                self.aliases[token.value] = module
                k += 1
            else:
                k += 1

    def _bind_module(self, i: int, name: str, close: int) -> None:
        t = self.toks
        module = _normalize(name)
        self.modules.add(module)
        suffix = ""
        if t[close + 1].value == "." and t[close + 2].kind == "id":
            if t[close + 2].value == "then" and t[close + 3].value == "(":
                fn = self.function_at(close + 4)
                if fn and fn.params and len(fn.params[0]) == 1:
                    self.aliases[fn.params[0][0]] = module
                return
            if t[close + 2].value != "promises":
                suffix = "." + t[close + 2].value
        j = i
        while t[j - 1].value in {".", "?."} and t[j - 2].kind == "id":
            j -= 2
        j -= 1
        if t[j].value == "await":
            j -= 1
        if t[j].value != "=":
            return
        target = t[j - 1]
        if target.kind == "id":
            self.aliases[target.value] = module + suffix
        elif target.value == "}":
            start = self.reverse.get(j - 1)
            if start is not None:
                for key, local in self._pattern_pairs(start):
                    self.aliases[local] = f"{module}{suffix}.{key}"

    def _bind_promisify(self, i: int) -> None:
        t = self.toks
        close = self.match.get(i + 1)
        if close is None:
            return
        equals = i - 1
        for _ in range(30):  # walk back past `util.` or `require("util").`
            if t[equals].value == "=" or equals < 1:
                break
            equals -= 1
        if t[equals].value != "=" or t[equals - 1].kind != "id":
            return
        chain = self.chain_at(close - 1) if t[close - 1].kind == "id" else []
        if chain:
            self.aliases[t[equals - 1].value] = self.resolve(chain)

    def _plain_chain(self, start: int) -> list[str] | None:
        """Return the names in `a.b.c` when that is the whole right-hand side."""
        t = self.toks
        chain = []
        k = start
        while t[k].kind == "id":
            chain.append(t[k].value)
            if t[k + 1].value != ".":
                k += 1
                break
            k += 2
        ended = t[k].value in {";", ",", "eof", ""} or t[k].line > t[k - 1].line
        return chain if chain and ended else None

    def _known(self, chain: list[str]) -> bool:
        return chain[0] in self.aliases or chain[0] in GLOBAL_SINKS or chain[0] in {"globalThis", "global", "window"}

    def _scan_aliases(self) -> None:
        t = self.toks
        for i in range(self.count):
            if t[i].kind != "id" or t[i].value not in {"const", "let", "var"}:
                continue
            k = i + 1
            if t[k].kind == "id" and t[k + 1].value == "=":
                chain = self._plain_chain(k + 2)
                if chain and self._known(chain):
                    self.aliases.setdefault(t[k].value, self.resolve(chain))
            elif t[k].value == "{":
                close = self.match.get(k)
                if close is not None and t[close + 1].value == "=":
                    chain = self._plain_chain(close + 2)
                    if chain and self._known(chain):
                        base = self.resolve(chain)
                        for key, local in self._pattern_pairs(k):
                            self.aliases.setdefault(local, f"{base}.{key}")

    def _scan_classes(self) -> None:
        t = self.toks
        for i in range(self.count):
            if t[i].kind == "id" and t[i].value == "class" and t[i + 1].kind == "id":
                if t[i + 2].value == "extends" and t[i + 3].kind == "id":
                    self.parents[t[i + 1].value] = t[i + 3].value
                for k in range(i + 2, min(i + 40, self.count)):
                    if t[k].value == "{":
                        self.class_spans.append((k, self.match.get(k, k), t[i + 1].value))
                        break
        self.class_starts = [span[0] for span in self.class_spans]

    def _enclosing_class(self, i: int) -> str:
        index = bisect.bisect_right(self.class_starts, i) - 1
        if index >= 0:
            start, end, name = self.class_spans[index]
            if start < i < end:
                return name
        return ""

    def _pattern_pairs(self, start: int) -> list[tuple[str, str]]:
        t = self.toks
        close = self.match.get(start, start)
        pairs: list[tuple[str, str]] = []
        k = start + 1
        while k < close:
            if t[k].value in ("{", "[", "("):
                nested = self.match.get(k, k)
                pairs.extend(self._pattern_pairs(k))
                k = nested + 1
                continue
            if t[k].kind == "id":
                if t[k + 1].value == ":" and t[k + 2].kind == "id":
                    pairs.append((t[k].value, t[k + 2].value))
                    k += 3
                    continue
                if t[k + 1].value == ":":
                    k += 2
                    continue
                pairs.append((t[k].value, t[k].value))
                if t[k + 1].value == "=":
                    k = self.expr_end(k + 2, close)
                    continue
            k += 1
        return pairs

    def pattern_names(self, start: int) -> list[str]:
        if self.toks[start].value == "[":
            close = self.match.get(start, start)
            return [t.value for t in self.toks[start + 1 : close] if t.kind == "id"]
        return [local for _, local in self._pattern_pairs(start)]

    def _remember(self, name: str, fn: Fn | None) -> None:
        if fn:
            fn.name = name
            self.functions.setdefault(name, fn)

    def _scan_functions(self) -> None:
        t = self.toks
        for i in range(self.count):
            token = t[i]
            if token.kind != "id":
                continue
            value = token.value
            nxt = t[i + 1].value
            if value == "function" and t[i + 1].kind == "id":
                self._remember(t[i + 1].value, self.function_at(i))
            elif nxt == "=" and t[i - 1].value in {"const", "let", "var"}:
                self._remember(value, self.function_at(i + 2))
            elif nxt == ":" and t[i - 1].value in {"const", "let", "var"}:
                k = i + 2
                steps = 0
                while steps < 80 and t[k].value not in {"=", ";"} and k < self.count:
                    k = self.match.get(k, k) + 1
                    steps += 1
                if t[k].value == "=":
                    self._remember(value, self.function_at(k + 1))
            elif nxt == "(" and value not in KEYWORDS and t[i - 1].value in METHOD_PREFIX:
                close = self.match.get(i + 1)
                if close is None:
                    continue
                body = self._body_after(close)
                if body is not None and t[body].value == "{":
                    fn = self._make_fn(i + 1, body)
                    self._remember(value, fn)
                    owner = self._enclosing_class(i)
                    if owner:
                        self.functions.setdefault(f"{owner}.{value}", fn)

    def _body_after(self, close: int) -> int | None:
        t = self.toks
        k = close + 1
        if t[k].value == ":":
            k = self._skip_return_type(k)
        return k if t[k].value == "{" else None

    def _skip_return_type(self, k: int) -> int:
        t = self.toks
        k += 1
        angle = 0
        steps = 0
        while k < self.count and steps < 200:
            value = t[k].value
            steps += 1
            if value == "<":
                angle += 1
            elif value == ">":
                angle -= 1
            elif value == ">>":
                angle -= 2
            elif value == "=>" and angle <= 0:
                return k
            elif value in ("(", "[", "{"):
                close = self.match.get(k, k)
                if value == "{" and angle <= 0 and t[close + 1].value != "=>":
                    return k
                k = close
            k += 1
        return k

    def function_at(self, i: int) -> Fn | None:
        t = self.toks
        if t[i].value == "async":
            i += 1
        if t[i].value == "function":
            i += 1
            if t[i].value == "*":
                i += 1
            if t[i].kind == "id":
                i += 1
            if t[i].value != "(":
                return None
            close = self.match.get(i)
            if close is None:
                return None
            body = self._body_after(close)
            return self._make_fn(i, body) if body is not None else None
        if t[i].value == "(":
            close = self.match.get(i)
            if close is None:
                return None
            k = close + 1
            if t[k].value == ":":
                k = self._skip_return_type(k)
            if t[k].value != "=>":
                return None
            return self._arrow(i, k)
        if t[i].kind == "id" and t[i + 1].value == "=>":
            return self._arrow(i, i + 1, single=t[i].value)
        return None

    def _arrow(self, params: int, arrow: int, single: str | None = None) -> Fn:
        t = self.toks
        names = [[single]] if single else self._params(params)
        body = arrow + 1
        if t[body].value == "{":
            return Fn(names, body + 1, self.match.get(body, self.count), t[params].line)
        return Fn(names, body, self.expr_end(body, self.count), t[params].line, expression=True)

    def _make_fn(self, params: int, body: int) -> Fn:
        return Fn(self._params(params), body + 1, self.match.get(body, self.count), self.toks[params].line)

    def _params(self, start: int) -> list[list[str]]:
        t = self.toks
        names: list[list[str]] = []
        for a, b in self.split_args(start):
            while a < b and t[a].value in {"public", "private", "protected", "readonly", "..."}:
                a += 1
            if a >= b:
                continue
            if t[a].value in ("{", "["):
                names.append(self.pattern_names(a))
            elif t[a].kind == "id":
                names.append([t[a].value])
        return names

    def split_args(self, start: int) -> list[tuple[int, int]]:
        """Return the token span of each top-level argument of a bracket pair."""
        t = self.toks
        close = self.match.get(start)
        if close is None or close == start + 1:
            return []
        spans = []
        a = start + 1
        k = a
        while k < close:
            if t[k].value in ("(", "[", "{"):
                k = self.match.get(k, k)
            elif t[k].value == ",":
                spans.append((a, k))
                a = k + 1
            k += 1
        if a < close:
            spans.append((a, close))
        return spans

    def expr_end(self, start: int, limit: int) -> int:
        t = self.toks
        k = start
        while k < limit:
            token = t[k]
            if token.value in ("(", "[", "{") and token.kind == "punct":
                k = self.match.get(k, k) + 1
                continue
            if token.kind == "punct" and token.value in (";", ",", ")", "]", "}"):
                return k
            if k > start and token.line > t[k - 1].line and _ends_expression(t[k - 1]) and not _continues(token):
                return k
            k += 1
        return limit

    def chain_at(self, i: int) -> list[str]:
        t = self.toks
        chain = [t[i].value]
        j = i
        while j >= 2 and t[j - 1].value in (".", "?.") and t[j - 2].kind == "id":
            chain.insert(0, t[j - 2].value)
            j -= 2
        if j >= 1 and t[j - 1].value in (".", "?."):
            chain.insert(0, self._module_from(j - 2) or "<expr>")
        return chain

    def _module_from(self, close: int) -> str:
        """Return the module in code such as require("fs").readFile or (await import("x")).y."""
        t = self.toks
        start = self.reverse.get(close)
        if start is None:
            return ""
        if t[start - 1].value in MODULE_LOADERS:
            return self._module_name(start, close)
        if t[start - 1].value == ")":
            outer = self.reverse.get(start - 1)
            if outer is not None and t[outer - 1].value == "createRequire":
                return self._module_name(start, close)
        if t[start + 1].value == "await" and t[start + 2].value == "import" and t[start + 3].value == "(":
            inner = self.match.get(start + 3)
            return self._module_name(start + 3, inner) if inner else ""
        return ""

    def _module_name(self, start: int, close: int) -> str:
        value = self.evaluate(start + 1, close)
        return _normalize(value) if isinstance(value, str) else ""

    def callee_at(self, i: int) -> list[str]:
        """Return the chain for a call whose name ends at token i."""
        t = self.toks
        token = t[i]
        if token.kind == "id":
            return self.chain_at(i)
        start = self.reverse.get(i)
        if start is None:
            return []
        if token.value == "]":
            key = self.evaluate(start + 1, i)
            if isinstance(key, str) and t[start - 1].kind == "id":
                return [*self.chain_at(start - 1), key]
            return []
        if token.value == ")":
            inner = t[start + 1 : i]
            if len(inner) == 3 and inner[1].value == "," and inner[2].kind == "id":
                return [inner[2].value]  # (0, eval)(code)
            if t[start - 1].value == "bind":
                return self.chain_at(start - 1)[:-1]
        return []

    def normalize(self, chain: list[str], args: list) -> tuple[list[str], list]:
        """Reduce exec.call(null, x), exec.apply(null, [x]) and Reflect.apply(exec, null, [x])."""
        if chain[-2:] == ["Reflect", "apply"] and len(args) >= 3:
            return self.callee_at(args[0][1] - 1), self.array_items(args[2])
        if len(chain) > 1 and chain[-1] == "call":
            return chain[:-1], args[1:]
        if len(chain) > 1 and chain[-1] == "apply":
            return chain[:-1], (self.array_items(args[1]) if len(args) > 1 else [])
        return chain, args

    def array_items(self, span: tuple[int, int]) -> list[tuple[int, int]]:
        return self.split_args(span[0]) if self.toks[span[0]].value == "[" else [span]

    def resolve(self, chain: list[str], tainted: dict | None = None) -> str:
        head, *rest = chain
        if tainted and head in tainted:
            return ".".join(["<tainted>", *rest])
        entry = self._table_entry(chain)
        if entry:
            return self.resolve(entry)
        base = self.aliases.get(head)
        name = ".".join([base, *rest]) if base else ".".join(chain)
        name = name.replace("fs.promises.", "fs.").replace(".default.", ".")
        if name.endswith("constructor.constructor"):
            return "Function"
        for prefix in GLOBAL_PREFIXES:
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    def _table_entry(self, chain: list[str]) -> list[str]:
        """Return exec for table.go when `const table = { go: exec }`."""
        span = self.constants.get(chain[0]) if len(chain) == 2 else None
        if span is None or self.toks[span[0]].value != "{":
            return []
        value = self._object_value(span[0], chain[1])
        if value is None:
            return []
        tokens = self.toks[value[0] : value[1]]
        names = [token.value for token in tokens if token.kind == "id"]
        return names if names and all(token.kind == "id" or token.value == "." for token in tokens) else []

    def new_class_before(self, i: int) -> str:
        """Return Runner for `new Runner(x).go`, where i is the token for go."""
        t = self.toks
        if t[i - 1].value in (".", "?.") and t[i - 2].value == ")":
            start = self.reverse.get(i - 2)
            if start is not None and t[start - 1].kind == "id" and t[start - 2].value == "new":
                return t[start - 1].value
        return ""

    def is_net_object(self, name: str) -> bool:
        """True for `const r = https.request(...)`, so r.write() counts as sending."""
        span = self.constants.get(name)
        if span is None:
            return False
        t = self.toks
        for k in range(span[0], min(span[1], span[0] + 12)):
            if t[k].kind == "id" and t[k + 1].value == "(":
                return self.resolve(self.chain_at(k)) in NET_CALLS
        return False

    def is_disguised(self, a: int, b: int, depth: int = 0) -> bool:
        for token in self.toks[a:b]:
            if (token.kind == "str" and token.escaped) or (token.kind == "punct" and token.value == "^"):
                return True
            if token.kind != "id":
                continue
            if token.value in DISGUISE_NAMES:
                return True
            if depth < 4:
                spans = list(self.appends.get(token.value, ()))
                if token.value in self.constants:
                    spans.append(self.constants[token.value])
                helper = self.functions.get(token.value)
                if helper:  # a local helper that does the decoding
                    spans.append((helper.start, helper.end))
                if any(self.is_disguised(*span, depth + 1) for span in spans[:32]):
                    return True
        return False

    def is_assembled(self, a: int, b: int) -> bool:
        """True when a string is put together rather than written out, like p.join("")."""
        value = self.evaluate(a, b)
        if not isinstance(value, (str, bytes)) or not value.strip():
            return False
        if b - a != 1:
            return True
        token = self.toks[a]
        span = self.constants.get(token.value) if token.kind == "id" else None
        return span is not None and span[1] - span[0] != 1

    def object_entries(self, start: int) -> list[tuple[str, tuple[int, int]]]:
        """List the top-level keys of an object literal, with the span of each value."""
        t = self.toks
        return [
            (t[a].value, (a + 2, b)) if t[a + 1].value == ":" else ("", (a, b))
            for a, b in self.split_args(start)
        ]

    def declare_tools(self, extension: Extension) -> None:
        if not self.imports_mcp:
            return
        t = self.toks
        for i in range(self.count):
            if t[i].value == "name" and t[i + 1].value == ":" and t[i + 2].kind == "str":
                for k in range(i + 3, min(i + 16, self.count)):
                    if t[k].value == "description" and t[k + 1].value == ":":
                        end = self.expr_end(k + 2, self.count)
                        self._add_tool(extension, t[i + 2].value, self._text(k + 2, end), t[i].line)
                        break

    def _add_tool(self, extension: Extension, name: str, description: str, line: int) -> None:
        extension.code_tool(name, description, self.file.path, line)

    def _text(self, a: int, b: int) -> str:
        return "".join(t.value for t in self.toks[a:b] if t.kind in {"str", "tpl"})

    def _object_value(self, start: int, key: str) -> tuple[int, int] | None:
        t = self.toks
        close = self.match.get(start)
        if close is None:
            return None
        k = start + 1
        while k < close:
            if t[k].value in ("(", "[", "{"):
                k = self.match.get(k, k) + 1
                continue
            if t[k].value == key and t[k + 1].value == ":":
                return k + 2, self.expr_end(k + 2, close)
            k += 1
        return None

    def _handler(self, span: tuple[int, int], project: Project) -> Fn | None:
        a, b = span
        fn = self.function_at(a)
        if fn:
            return fn
        if self.toks[a].kind == "id" and b == a + 1:
            found = project.find(self.toks[a].value, self)
            return found[1] if found and found[0] is self else None
        return None

    def registrations(self, project: Project):
        """Yield (tool name, handler, safe fields, checked fields) for MCP tools."""
        t = self.toks
        if not self.imports_mcp:
            return
        for i in range(self.count):
            token = t[i]
            if token.kind != "id" or t[i + 1].value != "(" or t[i - 1].value not in (".", "?."):
                continue
            if token.value in {"tool", "registerTool"}:
                yield from self._named_tool(i, project)
            elif token.value == "addTool":
                yield from self._object_tool(i, project)
            elif token.value == "setRequestHandler":
                args = self.split_args(i + 1)
                if len(args) == 2 and t[args[0][0]].value == "CallToolRequestSchema":
                    fn = self._handler(args[1], project)
                    if fn:
                        yield "tools/call handler", fn, set(), set()

    def _named_tool(self, i: int, project: Project):
        t = self.toks
        args = self.split_args(i + 1)
        if len(args) < 2 or t[args[0][0]].kind != "str":
            return
        name = t[args[0][0]].value
        description = ""
        safe: set[str] = set()
        checked: set[str] = set()
        for a, b in args[1:-1]:
            if t[a].kind in {"str", "tpl"}:
                description = self._text(a, b)
            elif t[a].value == "{":
                span = self._object_value(a, "description")
                if span:
                    description = self._text(*span)
                self._schema_fields(a, b, safe, checked)
        self._add_tool(project.extension, name, description, t[i].line)
        fn = self._handler(args[-1], project)
        if fn:
            yield name, fn, safe, checked

    def _object_tool(self, i: int, project: Project):
        t = self.toks
        args = self.split_args(i + 1)
        if not args or t[args[0][0]].value != "{":
            return
        start = args[0][0]
        name_span = self._object_value(start, "name")
        if not name_span:
            return
        name = self._text(*name_span)
        description_span = self._object_value(start, "description")
        self._add_tool(project.extension, name, self._text(*description_span) if description_span else "", t[i].line)
        safe: set[str] = set()
        checked: set[str] = set()
        self._schema_fields(*args[0], safe, checked)
        for key in ("execute", "handler", "run"):
            span = self._object_value(start, key)
            if span:
                fn = self._handler(span, project)
                if fn:
                    yield name, fn, safe, checked
                return

    def _schema_fields(self, a: int, b: int, safe: set[str], checked: set[str]) -> None:
        t = self.toks
        for k in range(a, b):
            if t[k].kind != "id" or t[k + 1].value != ":":
                continue
            end = self.expr_end(k + 2, b)
            segment = t[k + 2 : end]
            values = {s.value for s in segment}
            if len(segment) > 2 and segment[0].value == "z" and segment[2].value in SAFE_ZOD:
                safe.add(t[k].value)
            elif len(segment) > 3 and segment[0].value == "{" and segment[1].value == "type" and segment[3].value in {"number", "integer", "boolean"}:
                safe.add(t[k].value)
            elif values & CHECKED_ZOD and "z" in values:
                checked.add(t[k].value)


def _normalize(module: str) -> str:
    module = module.removeprefix("node:")
    return "fs" if module == "fs/promises" else module


def _ends_expression(token: Token) -> bool:
    return token.kind in {"id", "str", "tpl", "num", "regex"} or token.value in {")", "]", "}"}


def _continues(token: Token) -> bool:
    return token.kind == "punct" and token.value in {
        ".", "?.", "+", "-", "*", "/", "%", "&&", "||", "??", "?", ":", "=", "==", "===", "!=",
        "!==", "<", ">", "<=", ">=",
    }


class Flow:
    """Follow one tool's arguments through its handler and local helpers."""

    honors_sanitizers = True

    def __init__(self, project: Project, tool: str):
        self.project = project
        self.extension = project.extension
        self.tool = tool
        self.summaries: dict = {}
        self.fields: dict[str, str] = {}
        self.written: dict[str, str] = {}
        self.current: Unit | None = None
        self.depth = 0
        self.nesting = 0

    def enter(self, unit: Unit, fn: Fn, state: State, depth: int) -> Summary | None:
        key = (id(fn), frozenset(state.tainted))
        if key in self.summaries:
            return self.summaries[key]
        if depth > MAX_DEPTH:
            return None
        self.summaries[key] = None  # in progress: a recursive call falls back to guessing
        outer = (self.current, self.depth)
        self.current, self.depth = unit, depth
        self.walk(unit, fn.start, fn.end, state, depth)
        if fn.expression:
            state.returned = self.span(unit, fn.start, fn.end, state) or state.returned
        self.current, self.depth = outer
        summary = Summary(state.returned, set(state.validated))
        self.summaries[key] = summary
        return summary

    def walk(self, unit: Unit, start: int, end: int, state: State, depth: int) -> None:
        self.project.charge(end - start)
        t = unit.toks
        i = start
        self.nesting = 0
        while i < end:
            token = t[i]
            if token.kind == "punct" and token.value in {"{", "}"}:
                self.nesting += 1 if token.value == "{" else -1
            if token.kind == "id":
                value = token.value
                nxt = t[i + 1].value
                if value in {"const", "let", "var"}:
                    self.declare(unit, i, end, state)
                elif value == "for" and nxt == "(":
                    self.for_of(unit, i, state)
                elif value in {"if", "while"} and nxt == "(":
                    self.condition(unit, i, state)
                elif value == "return":
                    limit = unit.expr_end(i + 1, end)
                    state.returned = self.span(unit, i + 1, limit, state) or state.returned
                elif nxt == "=" and t[i - 1].value in {".", "?."} and t[i - 2].value == "this":
                    limit = unit.expr_end(i + 2, end)
                    origin = self.span(unit, i + 2, limit, state)
                    if origin:
                        self.fields[value] = origin
                elif nxt == "=" and t[i - 1].value not in {".", "?.", "const", "let", "var"}:
                    self.assign(unit, i, end, state)
                elif nxt == "+=" and t[i - 1].value not in {".", "?."}:
                    origin = self.span(unit, i + 2, unit.expr_end(i + 2, end), state)
                    if origin:
                        state.tainted[value] = origin
                if nxt == "(" and value not in KEYWORDS:
                    self.call(unit, i, state, depth)
            elif token.kind == "tpl" and t[i - 1].value == "$":
                self.tagged_shell(unit, i, state)
            elif token.kind == "punct" and token.value in {"]", ")"} and t[i + 1].value == "(":
                self.call(unit, i, state, depth)
            i += 1

    def declare(self, unit: Unit, i: int, limit: int, state: State) -> None:
        t = unit.toks
        k = i + 1
        if t[k].value in ("{", "["):
            names = unit.pattern_names(k)
            k = unit.match.get(k, k) + 1
        elif t[k].kind == "id":
            names = [t[k].value]
            k += 1
        else:
            return
        steps = 0
        while k < unit.count and (t[k].value == ":" or (steps and t[k].value not in {"=", ";"} and steps < 80)):
            k = unit.match.get(k, k) + 1
            steps += 1
        if k >= unit.count or t[k].value != "=":
            return
        rhs = k + 1
        if unit.function_at(rhs):
            return
        end = unit.expr_end(rhs, limit)
        origin = None if self.is_remote_result(unit, rhs) else self.span(unit, rhs, end, state)
        for name in names:
            if origin:
                state.tainted[name] = origin
            elif self.nesting <= 0:  # a clean value in one branch cannot clear the others
                state.tainted.pop(name, None)
        if origin and self.is_schema_parse(unit, rhs, end):
            state.validated.add(origin)
        if t[rhs].value == "new" and t[rhs + 1].kind == "id" and len(names) == 1:
            state.instances[names[0]] = t[rhs + 1].value

    def is_remote_result(self, unit: Unit, rhs: int) -> bool:
        """True for `await api.thing.fetch(id)`: the result is what the API returned,
        not the caller's argument. Awaited helpers that pass a value through still count."""
        t = unit.toks
        if t[rhs].value != "await":
            return False
        k = rhs + 1
        while t[k].kind == "id" and t[k + 1].value in (".", "?."):
            k += 2
        if t[k].kind != "id" or t[k + 1].value != "(" or k == rhs + 1:
            return False
        chain = unit.chain_at(k)
        return chain[0] not in {"this", "self"} and chain[-1] not in AWAIT_PASS_THROUGH

    def is_schema_parse(self, unit: Unit, a: int, b: int) -> bool:
        t = unit.toks
        for k in range(a, b):
            if t[k].value in {"parse", "safeParse", "parseAsync"} and t[k - 1].value == ".":
                if t[k - 2].value != "JSON":
                    return True
        return False

    def assign(self, unit: Unit, i: int, limit: int, state: State) -> None:
        name = unit.toks[i].value
        end = unit.expr_end(i + 2, limit)
        origin = None if self.is_remote_result(unit, i + 2) else self.span(unit, i + 2, end, state)
        if origin:
            state.tainted[name] = origin
        elif self.nesting <= 0:
            state.tainted.pop(name, None)

    def for_of(self, unit: Unit, i: int, state: State) -> None:
        t = unit.toks
        close = unit.match.get(i + 1)
        if close is None:
            return
        for k in range(i + 2, close):
            if t[k].value == "of" and t[k].kind == "id":
                origin = self.span(unit, k + 1, close, state)
                if origin:
                    for token in t[i + 2 : k]:
                        if token.kind == "id" and token.value not in {"const", "let", "var"}:
                            state.tainted[token.value] = origin
                return

    def condition(self, unit: Unit, i: int, state: State) -> None:
        """Record checks on tainted values. They lower severity but never clear a finding."""
        t = unit.toks
        close = unit.match.get(i + 1)
        if close is None:
            return
        for k in range(i + 2, close):
            if t[k].value in GUARD_METHODS and t[k + 1].value == "(" and t[k - 1].value == ".":
                inner = unit.match.get(k + 1, k + 1)
                origin = self.span(unit, k + 2, inner, state) or self.receiver_taint(unit, k, state)
                if origin and (t[k].value in {"startsWith", "test", "match"} or self.span(unit, k + 2, inner, state)):
                    state.validated.add(origin)
        self.magic_trigger(unit, i, close, state)

    def receiver_taint(self, unit: Unit, k: int, state: State) -> str | None:
        chain = unit.chain_at(k)
        return state.tainted.get(chain[0])

    def magic_trigger(self, unit: Unit, i: int, close: int, state: State) -> None:
        t = unit.toks
        for k in range(i + 2, close):
            if t[k].value not in {"===", "=="}:
                continue
            for side in (t[k - 1], t[k + 1]):
                if side.kind == "str" and len(side.value) >= 12 and " " not in side.value and entropy(side.value) >= 3.0:
                    if not self.span(unit, i + 2, close, state):
                        continue
                    start = close + 1
                    end = unit.match.get(start, unit.expr_end(start, unit.count)) if t[start].value == "{" else unit.expr_end(start, unit.count)
                    if _block_runs_code(unit, start, end):
                        self.extension.finding(
                            "backdoor.magic-trigger", "backdoor", Severity.HIGH,
                            "Hard-coded value unlocks command or code execution",
                            f"Tool '{self.tool}' compares its input to a fixed random-looking "
                            "string, then runs code. This is a classic backdoor shape.",
                            unit.file.path, t[i].line, unit.snippet(t[i].line),
                            "Find out why this branch exists before trusting the extension.",
                        )
                        return

    def span(self, unit: Unit, a: int, b: int, state: State) -> str | None:
        self.current = unit
        return self.tokens(_ternary_branches(unit.toks[a:b]), state)

    def source(self, seq: list[Token], i: int) -> str | None:
        return None

    def tokens(self, seq: list[Token], state: State) -> str | None:
        i = 0
        size = len(seq)
        self.project.charge(size)
        while i < size:
            token = seq[i]
            label = self.source(seq, i)
            if label:
                return label
            if token.kind == "tpl":
                for part in token.parts:
                    origin = self.tokens(part, state)
                    if origin:
                        return origin
            elif token.kind == "id":
                prev = seq[i - 1].value if i else ""
                nxt = seq[i + 1].value if i + 1 < size else ""
                if nxt == "(" and self.honors_sanitizers and _is_sanitizer(seq, i):
                    i = _skip_call(seq, i + 1)
                    continue
                if nxt == "(" and prev not in (".", "?."):
                    result = self.local_result(seq, i, state)
                    if result is not NOT_LOCAL:
                        if result:
                            return result
                        i = _skip_call(seq, i + 1)
                        continue
                if nxt == "[" and self.is_fixed_table(token.value, state):
                    i = _skip_index(seq, i + 1)  # a tainted key into a fixed table gives a fixed value
                    continue
                prop = seq[i + 2].value if i + 2 < size and nxt in (".", "?.") else ""
                if token.value == "this" and prop in self.fields:
                    return self.fields[prop]
                if token.value in state.instances and prop in self.fields:
                    return self.fields[prop]
                is_key = nxt == ":" and prev in {"{", ","}  # { name: value } is not a read of name
                if token.value in state.tainted and prev not in (".", "?.") and not is_key:
                    if prop in {"replace", "replaceAll"} and _strips_to_allowlist(seq, i + 3):
                        i = _skip_call(seq, i + 3)
                        continue
                    if prop not in state.safe and prop not in CLEAN_PROPERTIES:
                        return state.tainted[token.value]
            i += 1
        return None

    def is_fixed_table(self, name: str, state: State) -> bool:
        span = self.current.constants.get(name) if self.current else None
        return span is not None and name not in state.tainted and self.current.toks[span[0]].value in {"{", "["}

    def local_function(self, unit: Unit, name: str) -> tuple[Unit, Fn] | None:
        alias = unit.aliases.get(name, name)
        if name in unit.functions or alias.startswith("."):
            return self.project.find(alias.rsplit(".", 1)[-1], unit)
        return None

    def local_result(self, seq: list[Token], i: int, state: State):
        """Use a helper's summary: clean if it escapes or ignores its input."""
        target = self.local_function(self.current, seq[i].value)
        if target is None:
            return NOT_LOCAL
        end = _skip_call(seq, i + 1)
        parts = _split_top(seq[i + 2 : end - 1])
        summary = self.call_summary(target, [self.tokens(part, state) for part in parts], state)
        if summary is None:
            return NOT_LOCAL
        state.validated |= summary.validated
        return summary.returned

    def call_summary(self, target, taints: list, state: State) -> Summary | None:
        callee, fn = target
        tainted: dict[str, str] = {}
        for position, origin in enumerate(taints):
            if origin and position < len(fn.params):
                for name in fn.params[position]:
                    tainted[name] = origin
        inner = State(tainted, set(state.validated), via=(*state.via, fn.name or "helper"))
        return self.enter(callee, fn, inner, self.depth + 1)

    def report(self, unit: Unit, token: Token, rule, severity, title, origin, state, fix) -> None:
        detail = f"Tool '{self.tool}': argument '{origin}' reaches this call"
        detail += f" through {' > '.join(state.via)}." if state.via else "."
        if origin in state.validated:
            severity = severity.lowered()
            detail += " A check on this value appears earlier; confirm it is strict enough."
        self.extension.finding(rule, "input-validation", severity, title, detail, unit.file.path,
                               token.line, unit.snippet(token.line), fix)

    def reach(self, capability: str, unit: Unit, token: Token) -> None:
        self.extension.capability(capability, REACH_TOOL, unit.file.path, token.line, self.tool)

    def call(self, unit: Unit, i: int, state: State, depth: int) -> None:
        t = unit.toks
        close = unit.match.get(i + 1)
        if close is None:
            return
        if t[i].kind == "id" and t[close + 1].value == "{" and t[i - 1].value not in (".", "?.", "=", "(", "await", "return"):
            return
        if t[i].value == ")":  # ((c) => exec(c))(value), called on the spot
            fn = unit.function_at(unit.reverse.get(i, i) + 1)
            if fn:
                self.call_summary((unit, fn), [self.span(unit, a, b, state) for a, b in unit.split_args(i + 1)], state)
                return
        chain = unit.callee_at(i)
        if not chain:
            return
        args = unit.split_args(i + 1)
        chain, args = unit.normalize(chain, args)
        if not chain:
            return
        name = unit.resolve(chain, state.tainted)
        first = self.span(unit, *args[0], state) if args else None
        self.sink(unit, t[i], name, chain, args, first, state)
        self.extra(unit, i, chain, args, state)
        if len(chain) == 2 and chain[1] in MUTATORS and args:
            origin = next(filter(None, (self.span(unit, a, b, state) for a, b in args)), None)
            if origin:
                state.tainted[chain[0]] = origin
        if chain[-1] in HIGHER_ORDER and args:
            self.higher_order(unit, i, args[-1] if chain[-1] in {"on", "once"} else args[0], state)
        self.follow(unit, i, chain, args, state)

    def extra(self, unit: Unit, i: int, chain: list[str], args: list, state: State) -> None:
        pass

    def higher_order(self, unit: Unit, i: int, callback: tuple[int, int], state: State) -> None:
        """Handle [x].forEach(exec) and list.map((item) => exec(item))."""
        received = self.receiver(unit, i, state)
        if not received:
            return
        a, b = callback
        fn = unit.function_at(a)
        if fn:
            for name in (fn.params[0] if fn.params else []):
                state.tainted[name] = received
            return
        if unit.toks[b - 1].kind == "id":
            chain = unit.chain_at(b - 1)
            self.sink(unit, unit.toks[i], unit.resolve(chain), chain, [], received, state)

    def receiver(self, unit: Unit, i: int, state: State) -> str | None:
        """Taint of whatever a method is called on, walking back through a call chain."""
        t = unit.toks
        j = i - 2
        steps = 0
        while j > 0 and steps < 200:
            steps += 1
            if t[j].value in {")", "]"}:
                start = unit.reverse.get(j)
                if start is None:
                    break
                j = start - 1
            if t[j].kind == "id":
                j -= 1
            if t[j].value in {".", "?."}:
                j -= 1
                continue
            break
        return self.span(unit, j + 1, i - 1, state)

    def sink(self, unit: Unit, token: Token, name: str, chain: list[str], args: list, first, state: State) -> None:
        t = unit.toks
        if name in COMMAND_CALLS:
            self.reach(EXEC, unit, token)
            self.runs_written_file(unit, token, args, state)
        if name in SHELL_CALLS:
            if first:
                self.report(unit, token, "input.command-injection", Severity.CRITICAL,
                            "Tool argument reaches a shell command", first, state,
                            "Use execFile with a fixed program and an argument list.")
        elif name in SPAWN_CALLS:
            self.spawn_sink(unit, token, args, first, state)
        elif name in CODE_CALLS:
            self.reach(DYNAMIC, unit, token)
            if first:
                self.report(unit, token, "input.code-injection", Severity.CRITICAL,
                            "Tool argument is run as code", first, state,
                            "Never evaluate tool input.")
        elif name in MODULE_LOADERS and first:
            self.report(unit, token, "input.code-injection", Severity.CRITICAL,
                        "Tool argument chooses which module is loaded", first, state,
                        "Load modules from a fixed list.")
        elif name in TEMPLATE_CALLS and first:
            self.report(unit, token, "input.template-injection", Severity.HIGH,
                        "Tool argument is compiled as a template", first, state,
                        "Pass values into a fixed template instead.")
        elif name in DESERIALIZE_CALLS and first:
            self.report(unit, token, "input.unsafe-deserialization", Severity.HIGH,
                        "Tool argument is deserialized unsafely", first, state,
                        "Use JSON.parse on plain data.")
        elif name in READ_CALLS or name in WRITE_CALLS:
            writes = name in WRITE_CALLS
            self.reach(FS_WRITE if writes else FS_READ, unit, token)
            if any(t[k].kind in {"str", "tpl"} and SENSITIVE_PATH.search(t[k].value[:4096])
                   for a, b in args for k in range(a, min(b, a + 40))):
                self.reach(SECRETS, unit, token)
            if writes and len(args) > 1:
                origin = self.span(unit, *args[1], state)
                path = unit.evaluate(*args[0])
                if origin and isinstance(path, str):
                    self.written[path] = origin
            if first:
                action = "copy or move" if name in COPY_CALLS else "write or delete" if writes else "read"
                self.report(unit, token, "input.path-traversal",
                            Severity.HIGH if writes else Severity.MEDIUM,
                            f"Tool argument chooses which file to {action}", first, state,
                            "Resolve the path and confirm it stays inside an allowed folder.")
        elif name in NET_CALLS:
            self.reach(NET, unit, token)
            if first:
                self.extension.capability(UNTRUSTED, REACH_TOOL, unit.file.path, token.line,
                                          f"{self.tool} fetches a caller-chosen URL")
                self.report(unit, token, "input.ssrf", Severity.MEDIUM,
                            "Tool argument chooses which URL is requested", first, state,
                            "Allow only expected hosts and block private addresses.")
        elif len(chain) > 1 and chain[-1] in SQL_METHODS and SQL_RECEIVER.search(chain[-2]) and first and args:
            if t[args[0][0]].kind == "tpl" or args[0][1] - args[0][0] > 1:
                self.report(unit, token, "input.sql-injection", Severity.HIGH,
                            "Tool argument is built into a SQL statement", first, state,
                            "Pass values as bound parameters.")

    def runs_written_file(self, unit: Unit, token: Token, args: list, state: State) -> None:
        """Catch input saved to a file that a fixed command then runs."""
        if not self.written or not args:
            return
        value = unit.evaluate(*args[0])
        text = " ".join(str(item) for item in value) if isinstance(value, list) else value
        if isinstance(text, str):
            for path, origin in self.written.items():
                if path in text:
                    self.report(unit, token, "input.command-injection", Severity.CRITICAL,
                                "Tool argument is saved to a script that is then run", origin, state,
                                "Do not build scripts from tool input.")

    def spawn_sink(self, unit, token, args, first, state) -> None:
        fix = "Use a fixed program and validate each argument."
        toks = unit.toks
        shell_option = len(args) > 1 and any(
            toks[k].value == "shell" and toks[k + 2].value not in {"false", "undefined"}
            for a, b in args[1:] for k in range(a, b)
        )
        rest = next((o for a, b in args[1:] if (o := self.span(unit, a, b, state))), None)
        origin = first or rest
        if not origin:
            return
        if shell_option or _runs_inline(unit, args):
            self.report(unit, token, "input.command-injection", Severity.CRITICAL,
                        "Tool argument reaches a shell command", origin, state, fix)
        elif first:
            self.report(unit, token, "input.command-injection", Severity.HIGH,
                        "Tool argument chooses which program runs", origin, state, fix)
        else:
            self.report(unit, token, "input.argument-injection", Severity.MEDIUM,
                        "Tool argument is passed to a program without validation", origin, state,
                        "Validate the value and add '--' before it so it cannot act as a flag.")

    def tagged_shell(self, unit: Unit, i: int, state: State) -> None:
        token = unit.toks[i]
        if unit.aliases.get("$", "").split(".")[0] not in {"bun", "zx", "execa"}:
            return
        self.reach(EXEC, unit, token)
        origin = self.tokens([token], state)
        if origin:
            self.report(unit, token, "input.argument-injection", Severity.MEDIUM,
                        "Tool argument is placed in a shell template", origin, state,
                        "The template library escapes values, but flags can still be injected.")

    def follow(self, unit: Unit, i: int, chain: list[str], args: list, state: State) -> None:
        t = unit.toks
        owner = ""
        method = chain[-1]
        if t[i - 1].value == "new":
            owner, method = chain[-1], "constructor"
        elif chain[0] == "<expr>":
            owner = unit.new_class_before(i)
        elif chain[0] in state.instances:
            owner = state.instances[chain[0]]
        target = None
        if owner:
            for _ in range(6):  # walk up through parent classes
                target = self.project.find(f"{owner}.{method}", unit)
                owner = unit.parents.get(owner, "")
                if target is not None or not owner:
                    break
        elif len(chain) == 1:
            target = self.local_function(unit, chain[0])
        elif chain[0] in {"this", "self"}:
            target = self.project.find(chain[-1], unit)
        elif unit.aliases.get(chain[0], "").startswith("."):
            target = self.project.find(chain[-1], unit)
        elif len(chain) == 2:
            # Tools.go(x) on a class, or api.run(x) on an object literal.
            target = self.project.find(f"{chain[0]}.{chain[1]}", unit)
            if target is None and chain[0] in unit.constants:
                target = self.project.find(chain[1], unit)
        if target is not None:
            self.call_summary(target, [self.span(unit, a, b, state) for a, b in args], state)


class BehaviorFlow(Flow):
    """Track credentials toward the network, and downloaded data toward code execution.

    Same flow machinery as tool tracing, with different sources and sinks. It walks
    whole files because these behaviors matter whether or not a tool reaches them.
    Encoding a secret does not make it safe to send, so sanitizers clear nothing here.
    """

    honors_sanitizers = False

    def run(self, unit: Unit) -> None:
        self.current = unit
        self.walk(unit, 0, unit.count, State({}), 0)

    def source(self, seq: list[Token], i: int) -> str | None:
        token = seq[i]
        if token.kind in {"str", "tpl"}:
            return CREDENTIALS if CREDENTIAL_FILE.search(token.value[:4096]) else None
        if token.kind != "id":
            return None
        size = len(seq)
        if token.value == "process" and i + 2 < size:
            if seq[i + 2].value == "stdin":
                return STANDARD_INPUT
            if seq[i + 2].value == "env":
                following = seq[i + 3].value if i + 3 < size else ""
                if following in {".", "?."} and i + 4 < size:
                    return SECRET_VARIABLE if is_secret_name(seq[i + 4].value) else None
                return None if following == "[" else ENVIRONMENT
        if token.value in DOWNLOADERS and i + 1 < size and seq[i + 1].value == "(":
            return DOWNLOAD
        return None

    def is_remote_result(self, unit: Unit, rhs: int) -> bool:
        return False

    def magic_trigger(self, unit: Unit, i: int, close: int, state: State) -> None:
        pass

    def tagged_shell(self, unit: Unit, i: int, state: State) -> None:
        pass

    def leak(self, unit: Unit, token: Token, origin: str) -> None:
        self.extension.finding(
            "backdoor.exfiltration", "backdoor", EXFIL_SEVERITY[origin],
            f"Traced: {origin} sent over the network",
            EXFIL_DETAIL[origin], unit.file.path, token.line, unit.snippet(token.line),
            "Find out what this sends and why before trusting the extension.",
        )

    def extra(self, unit: Unit, i: int, chain: list[str], args: list, state: State) -> None:
        """Handle source.pipe(destination), where the data is the receiver, not an argument."""
        if chain[-1] == "pipe" and len(args) == 1 and unit.toks[args[0][0]].kind == "id":
            if unit.is_net_object(unit.toks[args[0][0]].value):
                origin = self.receiver(unit, i, state)
                if origin in EXFIL_DETAIL:
                    self.leak(unit, unit.toks[i], origin)

    def sink(self, unit: Unit, token: Token, name: str, chain: list[str], args: list, first, state: State) -> None:
        if name in CODE_CALLS or name in COMMAND_CALLS:
            if first == DOWNLOAD:
                self.extension.finding(
                    "backdoor.remote-code", "backdoor", Severity.CRITICAL,
                    f"Code downloaded from the network is passed to {name}",
                    "The code that runs can change at any time, and this scan never sees it.",
                    unit.file.path, token.line, unit.snippet(token.line),
                )
            return
        if name in NET_CALLS:
            for a, _ in args:  # https.get(url, (response) => ...) hands back downloaded data
                fn = unit.function_at(a)
                if fn:
                    for param in (fn.params[0] if fn.params else []):
                        state.tainted[param] = DOWNLOAD
        sends = name in NET_CALLS or name in DNS_CALLS or (
            len(chain) == 2 and chain[1] in {"write", "end", "send"} and unit.is_net_object(chain[0])
        )
        if not sends:
            return
        for index, (a, b) in enumerate(self.payload_spans(unit, args)):
            origin = self.span(unit, a, b, state)
            if origin == SECRET_VARIABLE and index == 0:
                continue  # some APIs, such as Telegram's, put the token in their own URL
            if origin in EXFIL_DETAIL:
                self.leak(unit, token, origin)
                return

    def payload_spans(self, unit: Unit, args: list) -> list[tuple[int, int]]:
        """Leave out request headers, where sending a key to its own service is normal."""
        spans: list[tuple[int, int]] = []
        for a, b in args:
            if unit.toks[a].value == "{":
                spans.extend(span for key, span in unit.object_entries(a) if key not in SIGNED_REQUEST_FIELDS)
            else:
                spans.append((a, b))
        return spans


def _runs_inline(unit: Unit, args: list) -> bool:
    """True for spawn("sh", ["-c", value]): an array, but a shell still parses the value."""
    if not args:
        return False
    items = list(args)
    if unit.toks[args[0][0]].value == "[":  # Bun.spawn(["sh", "-c", value])
        items = unit.array_items(args[0])
    elif len(args) > 1 and unit.toks[args[1][0]].value == "[":
        items = [args[0], *unit.array_items(args[1])]
    else:
        return False
    program = unit.evaluate(*items[0])
    if not isinstance(program, str):
        return False
    base = program.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if base not in INTERPRETERS:
        return False
    flags = (unit.toks[a].value.lower() for a, b in items[1:] if unit.toks[a].kind == "str")
    return any(flag in INLINE_FLAGS for flag in flags)


def _is_sanitizer(seq: list[Token], i: int) -> bool:
    name = seq[i].value
    if i >= 2 and seq[i - 1].value == "." and f"{seq[i - 2].value}.{name}" in SANITIZERS:
        return True
    return name in SANITIZERS


def _strips_to_allowlist(seq: list[Token], start: int) -> bool:
    """True for value.replace(/[^a-z0-9]/g, ""), which keeps only listed characters."""
    return (
        start + 1 < len(seq)
        and seq[start].value == "("
        and seq[start + 1].kind == "regex"
        and seq[start + 1].value.startswith("/[^")
    )


def _skip_call(seq: list[Token], start: int) -> int:
    depth = 0
    for k in range(start, len(seq)):
        if seq[k].value == "(":
            depth += 1
        elif seq[k].value == ")":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(seq)


def _skip_index(seq: list[Token], start: int) -> int:
    depth = 0
    for k in range(start, len(seq)):
        if seq[k].value == "[":
            depth += 1
        elif seq[k].value == "]":
            depth -= 1
            if depth == 0:
                return k + 1
    return len(seq)


def _ternary_branches(seq: list[Token]) -> list[Token]:
    """Drop the condition of `test ? a : b`: the result is a branch, not the test."""
    level = 0
    for index, token in enumerate(seq):
        if token.kind != "punct":
            continue
        if token.value in {"(", "[", "{"}:
            level += 1
        elif token.value in {")", "]", "}"}:
            level -= 1
        elif token.value == "?" and level == 0:
            return seq[index + 1 :]
    return seq


def _split_top(seq: list[Token]) -> list[list[Token]]:
    parts: list[list[Token]] = []
    current: list[Token] = []
    level = 0
    for token in seq:
        if token.kind == "punct":
            if token.value in {"(", "[", "{"}:
                level += 1
            elif token.value in {")", "]", "}"}:
                level -= 1
            elif token.value == "," and level == 0:
                parts.append(current)
                current = []
                continue
        current.append(token)
    if current:
        parts.append(current)
    return parts


def _block_runs_code(unit: Unit, start: int, end: int) -> bool:
    t = unit.toks
    for k in range(start, min(end, unit.count)):
        if t[k].kind == "id" and t[k + 1].value == "(":
            if unit.resolve(unit.chain_at(k)) in COMMAND_CALLS | CODE_CALLS:
                return True
    return False


def _file_pass(unit: Unit, extension: Extension) -> None:
    """Checks that apply to a whole file, whether or not a tool reaches the code."""
    t = unit.toks
    path = unit.file.path
    for i in range(unit.count):
        token = t[i]
        if token.kind == "id" and token.value == "if" and t[i + 1].value == "(":
            _time_trigger(unit, i, extension)
            continue
        if t[i + 1].value != "(":
            continue
        if token.kind == "id":
            if token.value in KEYWORDS:
                continue
        elif token.value not in {"]", ")"}:
            continue
        close = unit.match.get(i + 1)
        if close is None:
            continue
        if token.kind == "id" and t[close + 1].value == "{" and t[i - 1].value not in (".", "?.", "=", "(", "await", "return"):
            continue
        chain = unit.callee_at(i)
        if not chain:
            continue
        args = unit.split_args(i + 1)
        chain, args = unit.normalize(chain, args)
        if not chain:
            continue
        name = unit.resolve(chain)
        line = token.line
        if name in COMMAND_CALLS or name in CODE_CALLS:
            computed = token.value == "]" and unit.reverse.get(i, 0) + 2 != i
            if computed or name.split(".")[0] in unit.computed_modules:
                extension.finding(
                    "backdoor.dynamic-dispatch", "backdoor", Severity.HIGH,
                    f"The name of {name} is computed, which hides the call",
                    "Honest code has no need to assemble the name of a function that runs commands.",
                    path, line, unit.snippet(line),
                )
        if name in COMMAND_CALLS:
            extension.capability(EXEC, REACH_CODE, path, line)
            _constant_command(unit, token, args, extension)
        elif name in CODE_CALLS:
            extension.capability(DYNAMIC, REACH_CODE, path, line)
            _remote_code(unit, i, close, name, extension)
            _constant_code(unit, token, args, name, extension)
        elif name in READ_CALLS:
            extension.capability(FS_READ, REACH_CODE, path, line)
        elif name in WRITE_CALLS:
            extension.capability(FS_WRITE, REACH_CODE, path, line)
        elif name in NET_CALLS:
            extension.capability(NET, REACH_CODE, path, line)
            if args and unit.is_disguised(*args[0]):
                target = unit.evaluate(*args[0])
                extension.finding(
                    "backdoor.obfuscated-code", "backdoor", Severity.HIGH,
                    "A network address is disguised",
                    f"Worked out without running it: {clip(str(target), 120)}" if target else "The address is computed in a way that hides it.",
                    path, line, unit.snippet(line),
                )
        elif name.startswith("WebAssembly.") or chain[-1] == "_compile" or (name.endswith("Worker") and _worker_from_text(unit, args)):
            extension.finding(
                "backdoor.dynamic-loader", "backdoor", Severity.MEDIUM,
                f"{name} loads code at run time",
                "Code loaded this way cannot be read from the source.",
                path, line, unit.snippet(line),
            )
        elif len(chain) == 2 and chain[0] in {"console", "logger", "log"} and chain[1] in LOG_METHODS:
            _secret_in_log(unit, i, close, extension)
    if unit.aliases.get("$", "").split(".")[0] in {"bun", "zx", "execa"}:
        extension.capability(EXEC, REACH_CODE, path)
    _text_checks(unit.file, extension, unit.lines)


def _worker_from_text(unit: Unit, args: list) -> bool:
    return len(args) > 1 and any(
        unit.toks[k].value == "eval" and unit.toks[k + 2].value == "true" for k in range(*args[1])
    )


def _constant_command(unit: Unit, token: Token, args: list, extension: Extension) -> None:
    """Read commands written as constants, however they were put together."""
    if not args:
        return
    pieces = []
    for a, b in args[:2]:
        value = unit.evaluate(a, b)
        if isinstance(value, list):
            pieces.extend(str(item) for item in value)
        elif isinstance(value, (str, bytes)):
            pieces.append(value.decode("utf-8", "replace") if isinstance(value, bytes) else value)
    text = " ".join(pieces)
    if not text.strip():
        return
    if unit.is_disguised(*args[0]):
        extension.finding(
            "backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
            "A disguised command is decoded and run",
            f"Worked out without running it: {clip(text, 200)}",
            unit.file.path, token.line, unit.snippet(token.line),
        )
    shell.scan_command(extension, text, unit.file.path, token.line, REACH_CODE)


def _constant_code(unit: Unit, token: Token, args: list, name: str, extension: Extension) -> None:
    if args and any(t.kind == "id" and t.value in {"readFileSync", "readFile"} for t in unit.toks[args[0][0] : args[0][1]]):
        extension.finding(
            "backdoor.exec-data-file", "backdoor", Severity.MEDIUM,
            f"Code from another file is passed to {name}",
            "Whatever is in that file runs here, and it may not look like code to a reviewer.",
            unit.file.path, token.line, unit.snippet(token.line),
        )
    if not args or not (unit.is_disguised(*args[0]) or unit.is_assembled(*args[0])):
        return
    value = unit.evaluate(*args[0])
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else value if isinstance(value, str) else ""
    extension.finding(
        "backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
        f"Encoded data is decoded and passed to {name}",
        f"Worked out without running it: {clip(text, 200)}" if text else "Honest code rarely hides what it runs.",
        unit.file.path, token.line, unit.snippet(token.line),
    )


def _remote_code(unit: Unit, i: int, close: int, name: str, extension: Extension) -> None:
    t = unit.toks
    for k in range(i + 2, close):
        if t[k].kind == "id" and t[k].value in DOWNLOADERS:
            extension.finding(
                "backdoor.remote-code", "backdoor", Severity.CRITICAL,
                f"Code downloaded from the network is passed to {name}",
                "The code that runs can change at any time, and this scan never sees it.",
                unit.file.path, t[i].line, unit.snippet(t[i].line),
            )
            return


def _secret_in_log(unit: Unit, i: int, close: int, extension: Extension) -> None:
    t = unit.toks
    stack = list(t[i + 2 : close])
    while stack:
        token = stack.pop()
        if token.kind == "tpl":
            for part in token.parts:
                stack.extend(part)
        elif token.kind == "id" and is_secret_name(token.value):
            extension.finding(
                "opsec.secret-in-log", "opsec", Severity.MEDIUM,
                f"Logging call includes '{clip(token.value, 40)}'",
                "Logs are often copied into bug reports and support tickets.",
                unit.file.path, t[i].line, unit.snippet(t[i].line),
                "Remove the value from the log line.",
            )
            return


def _time_trigger(unit: Unit, i: int, extension: Extension) -> None:
    t = unit.toks
    close = unit.match.get(i + 1)
    if close is None:
        return
    condition = t[i + 2 : close]
    uses_date = any(token.value == "Date" for token in condition)
    fixed = any(
        (token.kind == "num" and len(token.value) >= 10)
        or (token.kind == "str" and re.match(r"\d{4}-\d{2}-\d{2}", token.value))
        for token in condition
    )
    if not (uses_date and fixed):
        return
    start = close + 1
    end = unit.match.get(start, start) if t[start].value == "{" else unit.expr_end(start, unit.count)
    if _block_runs_code(unit, start, end):
        extension.finding(
            "backdoor.time-trigger", "backdoor", Severity.MEDIUM,
            "Command or code execution depends on the date or time",
            "Delayed behavior can stay hidden during review and testing.",
            unit.file.path, t[i].line, unit.snippet(t[i].line),
        )


def _text_checks(file: PackageFile, extension: Extension, lines: list[str]) -> None:
    path = file.path
    lines = lines or file.text.splitlines()
    obfuscated = 0
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("//", "*", "/*")):
            continue
        obfuscated += len(OBFUSCATOR_NAME.findall(line))
        line = line[:MAX_LINE]
        if TLS_OFF.search(line):
            extension.finding("opsec.tls-disabled", "opsec", Severity.MEDIUM,
                              "TLS certificate checks are turned off",
                              "Traffic can be intercepted without any warning.",
                              path, number, clip(line), "Remove this setting.")
        if BIND_ALL.search(line):
            extension.finding("opsec.bind-all", "opsec", Severity.MEDIUM,
                              "Server listens on every network interface",
                              "Other devices on the network may be able to reach it.",
                              path, number, clip(line), "Bind to 127.0.0.1.")
        if CORS_ANY.search(line):
            extension.finding("opsec.cors-any", "opsec", Severity.MEDIUM,
                              "Local server accepts requests from any website",
                              "Any page open in a browser may be able to call it.",
                              path, number, clip(line), "Allow only known origins.")
        if ENV_DUMP.search(line):
            extension.finding("backdoor.env-dump", "backdoor", Severity.MEDIUM,
                              "Whole environment is read or serialized",
                              "Environment variables usually hold API keys. Check where this value goes.",
                              path, number, clip(line), "Read only the variables the extension needs.")
        if DECODE_EVAL.search(line):
            extension.finding("backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
                              "Encoded data is decoded and run",
                              "Honest code rarely hides what it runs.",
                              path, number, clip(line))
    if obfuscated >= 20:
        extension.finding("backdoor.obfuscator", "backdoor", Severity.HIGH,
                          "Code looks machine-obfuscated",
                          f"Found {obfuscated} generated names such as _0x1a2b. Review is not "
                          "practical until you have the original source.",
                          path)
        extension.gap(path, "obfuscated code cannot be reviewed reliably")
