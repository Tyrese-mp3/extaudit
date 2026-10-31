"""Python analysis with the standard ast module. Target code is parsed, never imported."""

from __future__ import annotations

import ast
import re
import warnings
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
from .python_eval import DECODERS as CONSTANT_DECODERS
from .python_eval import Evaluator

MAX_DEPTH = 5
MAX_WORK = 4_000_000

SHELL_CALLS = {
    "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell", "commands.getoutput",
}
SPAWN_CALLS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "asyncio.create_subprocess_exec", "os.execv", "os.execvp", "os.execve",
    "os.execvpe", "os.spawnv", "os.spawnvp", "os.posix_spawn", "pty.spawn", "os.startfile",
}
POSITIONAL_EXEC = {"os.execl", "os.execle", "os.execlp", "os.execlpe", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe"}
COMMAND_CALLS = SHELL_CALLS | SPAWN_CALLS | POSITIONAL_EXEC
CODE_CALLS = {"eval", "exec", "compile", "__import__", "runpy.run_path", "runpy.run_module", "importlib.import_module"}
DESERIALIZE_CALLS = {
    "pickle.load", "pickle.loads", "marshal.load", "marshal.loads", "shelve.open",
    "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "pandas.read_pickle",
    "joblib.load", "torch.load", "yaml.unsafe_load", "yaml.full_load",
}
TEMPLATE_CALLS = {"jinja2.Template", "mako.template.Template", "tornado.template.Template"}
READ_CALLS = {"os.listdir", "os.walk", "os.scandir", "glob.glob", "glob.iglob", "os.stat"}
WRITE_CALLS = {
    "os.remove", "os.unlink", "os.rmdir", "os.rename", "os.replace", "os.makedirs", "os.mkdir",
    "os.chmod", "shutil.rmtree", "shutil.move", "shutil.copy", "shutil.copy2", "shutil.copyfile",
    "shutil.copytree", "shutil.unpack_archive",
}
COPY_CALLS = {"os.rename", "os.replace", "shutil.move", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree"}
AWAIT_PASS_THROUGH = {"resolve", "normalize", "validate", "model_validate", "parse", "parse_obj"}
READ_METHODS = {"read_text", "read_bytes", "iterdir", "rglob"}
WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "touch", "extractall", "extract"}
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "options", "request", "stream"}
NET_CALLS = {
    "urllib.request.urlopen", "urllib.request.urlretrieve", "socket.socket",
    "socket.create_connection", "ftplib.FTP", "smtplib.SMTP", "smtplib.SMTP_SSL",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "aiohttp.ClientSession",
    "urllib3.request",
}
NET_MODULES = {"requests", "httpx"}
HTTP_RECEIVER_HINTS = ("session", "client", "http")
SEND_METHODS = {"sendall", "sendto", "sendmail", "send_message"}
DNS_CALLS = {"socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo", "dns.resolver.resolve"}
MUTATORS = {"append", "appendleft", "extend", "insert", "add", "update", "setdefault"}
HEX_ESCAPES = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
SQL_METHODS = {"execute", "executemany", "executescript"}
SQL_RECEIVER_HINTS = ("cursor", "cur", "conn", "db", "database", "engine", "session")
SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "ord", "hash", "isinstance", "any", "all",
    "shlex.quote", "shlex.join", "os.path.basename", "os.path.exists", "os.path.isfile",
    "os.path.isdir", "urllib.parse.quote", "urllib.parse.quote_plus", "html.escape", "re.escape",
    "uuid.UUID", "secure_filename", "werkzeug.utils.secure_filename", "ipaddress.ip_address",
}
CLEAN_METHODS = {
    "startswith", "endswith", "isdigit", "isalnum", "isalpha", "isnumeric", "exists", "is_file",
    "is_dir", "is_absolute", "is_relative_to", "count", "find", "index",
}
GUARD_METHODS = {
    "is_relative_to", "startswith", "fullmatch", "match", "search", "isdigit", "isalnum",
    "isidentifier", "isnumeric", "commonpath",
}
DECODERS = {*CONSTANT_DECODERS, "codecs.decode", "marshal.loads"}
LOADER_CALLS = {"types.FunctionType", "types.CodeType", "marshal.loads", "marshal.load"}
PARTIAL = {"functools.partial", "partial"}
SCOPE_TABLES = {"globals", "locals", "vars", "__builtins__", "builtins"}
BUILTIN_PREFIXES = ("builtins.", "__builtins__.", "__builtin__.")
INTERPRETERS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe",
    "pwsh", "pwsh.exe", "python", "python3", "python.exe", "node", "node.exe", "perl", "ruby", "php",
}
INLINE_FLAGS = {"-c", "/c", "/k", "-command", "-encodedcommand", "-e", "--eval", "-lc", "-ic", "-ec"}
SAFE_ANNOTATIONS = {"int", "float", "bool", "UUID"}
LOG_CALLS = {"print", "pprint"}
LOG_ROOTS = {"logging", "logger", "log", "_logger", "LOG", "LOGGER"}
CLOCK_CALLS = {"datetime.now", "datetime.utcnow", "datetime.datetime.now", "datetime.datetime.utcnow",
               "time.time", "date.today", "datetime.date.today"}

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
SIGNED_REQUEST_FIELDS = {"headers", "auth", "cookies", "cert", "timeout", "verify"}


def analyze(extension: Extension) -> None:
    project = Project(extension)
    for file in extension.files:
        if file.suffix in {".py", ".pyw"}:
            project.add(file)
    for module in project.modules:
        if not is_test_path(module.file.path):
            _file_pass(module, extension)
    try:
        for module in project.modules:
            if not is_test_path(module.file.path):
                _trace_behavior(project, module)
    except TooComplex:
        extension.gap("behavior tracing", "code is too complex to trace fully; some files were not followed")
    project.work = 0  # tool tracing gets its own budget
    try:
        for module, function, tool in project.handlers():
            trace = Trace(project, tool)
            try:
                trace.start(module, function)
            except RecursionError:
                extension.gap(f"{module.file.path}:{function.lineno}", "code is nested too deeply to trace")
    except TooComplex:
        extension.gap("tool tracing", "code is too complex to trace fully; some tools were not followed")


def _trace_behavior(project: "Project", module: "Module") -> None:
    """Look for credentials leaving the machine and downloaded code being run."""
    trace = Trace(project, "", BehaviorWalker)
    try:
        BehaviorWalker(trace, module, State({}, set()), 0).block(module.tree.body)
    except RecursionError:
        project.extension.gap(module.file.path, "code is nested too deeply to trace")


def dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class Module:
    def __init__(self, file: PackageFile, tree: ast.Module):
        self.file = file
        self.tree = tree
        self.lines = file.text.splitlines()
        self.aliases: dict[str, str] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.classes: set[str] = set()
        self.bases: dict[str, list[str]] = {}
        self.methods: dict[tuple[str, str], ast.AST] = {}
        self.assigned: dict[str, ast.expr] = {}
        for node in ast.walk(tree):
            self._index(node)
        self.evaluator = Evaluator(self.resolve, self.assigned)

    def _index(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            for item in node.names:
                self.aliases[item.asname or item.name.split(".")[0]] = (
                    item.name if item.asname else item.name.split(".")[0]
                )
        elif isinstance(node, ast.ImportFrom):
            prefix = "." * node.level + (node.module or "")
            for item in node.names:
                self.aliases[item.asname or item.name] = f"{prefix}.{item.name}"
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.functions.setdefault(node.name, node)
        elif isinstance(node, ast.ClassDef):
            self.classes.add(node.name)
            self.bases[node.name] = [(dotted(base) or "").rsplit(".", 1)[-1] for base in node.bases]
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.methods[(node.name, item.name)] = item
        elif isinstance(node, ast.Assign):
            if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                self.assigned[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value is not None:
                self.assigned[node.target.id] = node.value
        elif isinstance(node, ast.AugAssign):
            if isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
                previous = self.assigned.get(node.target.id)
                if previous is not None:
                    self.assigned[node.target.id] = ast.BinOp(previous, ast.Add(), node.value)

    def evaluate(self, node: ast.AST | None):
        return self.evaluator.evaluate(node)

    def resolve(self, node: ast.AST) -> str:
        """Name what a call really targets, seeing through aliases and dynamic lookups."""
        name = self._resolve(node, 0)
        for prefix in BUILTIN_PREFIXES:
            if name.startswith(prefix):
                return name[len(prefix):]
        return name

    def _resolve(self, node: ast.AST, depth: int) -> str:
        if depth > 12:
            return ""
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            bound = self.assigned.get(node.id)
            if isinstance(bound, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
                target = self._resolve(bound, depth + 1)
                if target:
                    return target
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value, depth + 1)
            return f"{base}.{node.attr}" if base else ""
        if isinstance(node, ast.Subscript):
            key = self.evaluate(node.slice)
            base = self._resolve(node.value, depth + 1)
            if isinstance(key, str):
                if base == "sys.modules" or base in SCOPE_TABLES:
                    return key
                if base.endswith(".__dict__"):
                    return f"{base[:-9]}.{key}"
                table = self.assigned.get(node.value.id) if isinstance(node.value, ast.Name) else None
                if isinstance(table, ast.Dict):
                    for entry, value in zip(table.keys, table.values):
                        if isinstance(entry, ast.Constant) and entry.value == key:
                            return self._resolve(value, depth + 1)
            return ""
        if isinstance(node, ast.Call):
            return self._resolve_call(node, depth)
        return ""

    def _resolve_call(self, node: ast.Call, depth: int) -> str:
        function = self._resolve(node.func, depth + 1)
        first = node.args[0] if node.args else None
        if function in {"__import__", "importlib.import_module", "importlib.__import__", "builtins.__import__"}:
            value = self.evaluate(first)
            return value if isinstance(value, str) else ""
        if function == "getattr" and len(node.args) >= 2:
            base = self._resolve(first, depth + 1)
            attribute = self.evaluate(node.args[1])
            return f"{base}.{attribute}" if base and isinstance(attribute, str) else ""
        if function in PARTIAL and first is not None:
            return self._resolve(first, depth + 1)
        if function in SCOPE_TABLES:
            if function == "vars" and first is not None:
                base = self._resolve(first, depth + 1)
                return f"{base}.__dict__" if base else ""
            return function
        return ""

    def snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        return clip(self.lines[line - 1]) if 0 < line <= len(self.lines) else ""


class TooComplex(Exception):
    """The work budget ran out, so a crafted call graph cannot stall the scan."""


class Project:
    def __init__(self, extension: Extension):
        self.extension = extension
        self.modules: list[Module] = []
        self.work = 0

    def charge(self) -> None:
        self.work += 1
        if self.work > MAX_WORK:
            raise TooComplex

    def add(self, file: PackageFile) -> None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # the scanned file's problems, not the user's
                tree = ast.parse(file.text)
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            self.extension.gap(file.path, "Python could not be parsed, so it was not analyzed")
            return
        self.modules.append(Module(file, tree))

    def find(self, name: str, near: Module) -> tuple[Module, ast.AST] | None:
        if name in near.functions:
            return near, near.functions[name]
        matches = [m for m in self.modules if name in m.functions]
        return (matches[0], matches[0].functions[name]) if len(matches) == 1 else None

    def find_method(self, owner: str, name: str, near: Module) -> tuple[Module, ast.AST] | None:
        pending = [owner]
        seen: set[str] = set()
        while pending:  # walk up through base classes
            current = pending.pop(0)
            if current in seen:
                continue
            seen.add(current)
            for module in (near, *self.modules):
                if (current, name) in module.methods:
                    return module, module.methods[(current, name)]
                pending.extend(module.bases.get(current, ()))
        return None

    def is_class(self, name: str, near: Module) -> bool:
        return name in near.classes or any(name in m.classes for m in self.modules)

    def handlers(self):
        """Yield (module, function, tool name) for every MCP tool handler."""
        for module in self.modules:
            if is_test_path(module.file.path):
                continue
            imports_mcp = any(
                root in value for value in module.aliases.values()
                for root in ("mcp", "fastmcp", "claude_agent_sdk")
            )
            for function in module.functions.values():
                for decorator in function.decorator_list:
                    tool = self._tool_from_decorator(module, function, decorator, imports_mcp)
                    if tool:
                        yield module, function, tool
            for node in ast.walk(module.tree):
                if not isinstance(node, ast.Call):
                    continue
                name = dotted(node.func) or ""
                tail = name.rsplit(".", 1)[-1]
                if tail == "add_tool" and node.args and isinstance(node.args[0], ast.Name):
                    target = module.functions.get(node.args[0].id)
                    if target:
                        self._declare(module, target, target.name, ast.get_docstring(target) or "")
                        yield module, target, target.name
                elif tail == "Tool":
                    self._declare_tool_object(module, node)

    def _tool_from_decorator(self, module, function, decorator, imports_mcp) -> str:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted(target) or ""
        tail = name.rsplit(".", 1)[-1]
        if tail not in {"tool", "call_tool"} or ("." not in name and not imports_mcp):
            return ""
        if tail == "call_tool":
            return function.name
        tool_name = function.name
        description = ast.get_docstring(function) or ""
        if isinstance(decorator, ast.Call):
            if decorator.args and _text(decorator.args[0]):
                tool_name = _text(decorator.args[0])
            if len(decorator.args) > 1 and _text(decorator.args[1]):
                description = _text(decorator.args[1])
            for keyword in decorator.keywords:
                if keyword.arg == "name" and _text(keyword.value):
                    tool_name = _text(keyword.value)
                elif keyword.arg == "description" and _text(keyword.value):
                    description = _text(keyword.value)
        self._declare(module, function, tool_name, description)
        return tool_name

    def _declare_tool_object(self, module: Module, node: ast.Call) -> None:
        fields = {k.arg: _text(k.value) for k in node.keywords if k.arg in {"name", "description"}}
        if fields.get("name"):
            self._add_tool(module, node.lineno, fields["name"], fields.get("description", ""))

    def _declare(self, module, function, name, description) -> None:
        self._add_tool(module, function.lineno, name, description)

    def _add_tool(self, module, line, name, description) -> None:
        self.extension.code_tool(name, description, module.file.path, line)


def _text(node: ast.AST) -> str:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else ""


@dataclass
class State:
    tainted: dict[str, str]
    validated: set[str]
    instances: dict[str, str] = field(default_factory=dict)
    via: tuple[str, ...] = ()
    handles: dict[str, ast.expr] = field(default_factory=dict)


@dataclass
class Summary:
    """What a helper does with its input, so callers need not guess."""

    returned: str | None
    validated: set[str]


class Trace:
    """Follow tool arguments forward through one handler and the helpers it calls."""

    def __init__(self, project: Project, tool: str, walker: type | None = None):
        self.project = project
        self.extension = project.extension
        self.tool = tool
        self.walker = walker or Walker
        self.summaries: dict = {}
        self.fields: dict[str, str] = {}
        self.written: dict[str, str] = {}

    def start(self, module: Module, function) -> None:
        arguments = function.args
        tainted: dict[str, str] = {}
        validated: set[str] = set()
        for arg in [*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs]:
            if arg.arg in {"self", "cls"} or _is_context(arg):
                continue
            if _safe_annotation(arg.annotation):
                continue
            tainted[arg.arg] = arg.arg
            if arg.annotation is not None and _has_pattern(arg.annotation):
                validated.add(arg.arg)
        if arguments.kwarg:
            tainted[arguments.kwarg.arg] = arguments.kwarg.arg
        self.enter(module, function, State(tainted, validated), 0)

    def enter(self, module: Module, function, state: State, depth: int) -> Summary | None:
        key = (id(function), frozenset(state.tainted))
        if key in self.summaries:
            return self.summaries[key]
        if depth > MAX_DEPTH:
            return None
        self.summaries[key] = None  # in progress: a recursive call falls back to guessing
        walker = self.walker(self, module, state, depth)
        walker.block(function.body)
        summary = Summary(walker.returned, set(state.validated))
        self.summaries[key] = summary
        return summary


class Walker:
    honors_sanitizers = True

    def __init__(self, trace: Trace, module: Module, state: State, depth: int):
        self.trace = trace
        self.module = module
        self.state = state
        self.depth = depth
        self.extension = trace.extension
        self.returned: str | None = None
        self.lambdas: set[int] = set()

    def block(self, body: list[ast.stmt]) -> None:
        for statement in body:
            self.statement(statement)

    def statement(self, node: ast.stmt) -> None:
        self.trace.project.charge()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.function(node)
        elif isinstance(node, ast.ClassDef):
            self.block(node.body)
        elif isinstance(node, ast.Assign):
            self.scan(node.value)
            origin = self.taint(node.value)
            for target in node.targets:
                self.bind(target, origin)
                self.note_instance(target, node.value)
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.value is not None:
                self.scan(node.value)
                origin = self.taint(node.value)
                if origin or isinstance(node, ast.AnnAssign):
                    self.bind(node.target, origin)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            self.scan(node.iter)
            self.bind(node.target, self.taint(node.iter))
            self.block(node.body)
            self.block(node.orelse)
        elif isinstance(node, ast.While):
            self.scan(node.test)
            self.guards(node.test)
            self.block(node.body)
            self.block(node.orelse)
        elif isinstance(node, ast.If):
            self.scan(node.test)
            self.guards(node.test)
            self.magic_trigger(node)
            self.branches([node.body, node.orelse])
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self.scan(item.context_expr)
                if item.optional_vars is not None:
                    self.bind(item.optional_vars, self.taint(item.context_expr))
                    if isinstance(item.optional_vars, ast.Name):
                        self.state.handles[item.optional_vars.id] = item.context_expr
            self.block(node.body)
        elif isinstance(node, (ast.Try, ast.TryStar)):
            self.block(node.body)
            self.branches([*(handler.body for handler in node.handlers), node.orelse])
            self.block(node.finalbody)
        elif isinstance(node, ast.Match):
            self.scan(node.subject)
            origin = self.taint(node.subject)
            if origin:
                for case in node.cases:
                    for part in ast.walk(case.pattern):
                        captured = getattr(part, "name", None) or getattr(part, "rest", None)
                        if captured:
                            self.state.tainted[captured] = origin
            self.branches([case.body for case in node.cases])
        elif isinstance(node, ast.Assert):
            self.scan(node.test)
            self.guards(node.test)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                self.scan(node.value)
                self.returned = self.taint(node.value) or self.returned
        elif isinstance(node, (ast.Expr, ast.Raise)):
            value = node.exc if isinstance(node, ast.Raise) else node.value
            if value is not None:
                self.scan(value)

    def function(self, node) -> None:
        self.block(node.body)  # closures see the enclosing tainted names

    def branches(self, blocks: list[list[ast.stmt]]) -> None:
        """Walk alternatives separately, so a clean value in one cannot erase taint from another."""
        start = dict(self.state.tainted)
        merged = dict(start)
        for block in blocks:
            self.state.tainted = dict(start)
            self.block(block)
            merged.update(self.state.tainted)
        self.state.tainted = merged

    def bind(self, target: ast.expr, origin: str | None) -> None:
        tainted = self.state.tainted
        if isinstance(target, ast.Name):
            if origin:
                tainted[target.id] = origin
            else:
                tainted.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.bind(item.value if isinstance(item, ast.Starred) else item, origin)
        elif isinstance(target, ast.Attribute):
            if origin and (dotted(target) or "").split(".")[0] in {"self", "cls"}:
                self.trace.fields[target.attr] = origin
        elif isinstance(target, ast.Subscript) and origin:
            self.bind(target.value, origin)

    def note_instance(self, target: ast.expr, value: ast.expr) -> None:
        if isinstance(target, ast.Name) and isinstance(value, ast.Call):
            owner = self.class_of(value)
            if owner:
                self.state.instances[target.id] = owner

    def class_of(self, call: ast.Call) -> str:
        name = self.module.resolve(call.func).rsplit(".", 1)[-1]
        return name if name and self.trace.project.is_class(name, self.module) else ""

    def taint(self, node: ast.AST | None) -> str | None:
        self.trace.project.charge()
        if node is None or isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.Name):
            return self.state.tainted.get(node.id)
        if isinstance(node, ast.Await) and _is_remote_result(node.value):
            return None
        if isinstance(node, ast.Call):
            return self.call_taint(node)
        if isinstance(node, ast.Attribute):
            return self.attribute_taint(node)
        if isinstance(node, ast.Subscript):
            return self.taint(node.value)  # a tainted key into a fixed table gives a fixed value
        if isinstance(node, ast.IfExp):
            return self.taint(node.body) or self.taint(node.orelse)
        if isinstance(node, (ast.Compare, ast.Lambda)):
            return None
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return None
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            for generator in node.generators:
                self.bind(generator.target, self.taint(generator.iter))
        for child in ast.iter_child_nodes(node):
            origin = self.taint(child)
            if origin:
                return origin
        return None

    def attribute_taint(self, node: ast.Attribute) -> str | None:
        name = dotted(node) or ""
        head = name.split(".")[0]
        if (head in {"self", "cls"} or head in self.state.instances) and node.attr in self.trace.fields:
            return self.trace.fields[node.attr]
        return self.taint(node.value)

    def call_taint(self, node: ast.Call) -> str | None:
        name = self.module.resolve(node.func)
        if self.honors_sanitizers:
            if name in SANITIZERS or name.rsplit(".", 1)[0] == "hashlib":
                return None
            if name == "re.sub" and node.args and _text(node.args[0]).startswith("[^"):
                return None  # keeps only the characters it lists
        target = self.local_target(node, name)
        if target is not None and not self.class_of(node):
            summary = self.follow(node, target)
            if summary is not None:
                self.state.validated |= summary.validated
                return summary.returned
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in CLEAN_METHODS:
                return None
            origin = self.taint(node.func.value)
            if origin:
                return origin
        for arg in [*node.args, *(k.value for k in node.keywords)]:
            origin = self.taint(arg)
            if origin:
                return origin
        return None

    def scan(self, expression: ast.AST) -> None:
        nodes = list(ast.walk(expression))
        for node in nodes:
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                for generator in node.generators:
                    self.bind(generator.target, self.taint(generator.iter))
            elif isinstance(node, ast.NamedExpr):
                self.bind(node.target, self.taint(node.value))
            elif isinstance(node, (ast.Yield, ast.YieldFrom)) and node.value is not None:
                self.returned = self.taint(node.value) or self.returned
        for node in reversed(nodes):  # inner calls first, as they run
            if isinstance(node, ast.Call):
                self.check_call(node)

    def guards(self, test: ast.AST) -> None:
        """Note checks on tainted values. A check is recorded, never assumed sufficient."""
        for node in ast.walk(test):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in GUARD_METHODS:
                    for part in [node.func.value, *node.args]:
                        origin = self.taint_guarded(part)
                        if origin:
                            self.state.validated.add(origin)
            elif isinstance(node, ast.Compare):
                if any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
                    origin = self.taint(node.left)
                    if origin:
                        self.state.validated.add(origin)

    def taint_guarded(self, node: ast.AST) -> str | None:
        # A guard call such as path.resolve() still names the value being checked.
        for part in ast.walk(node):
            if isinstance(part, ast.Name) and part.id in self.state.tainted:
                return self.state.tainted[part.id]
        return None

    def magic_trigger(self, node: ast.If) -> None:
        for compare in ast.walk(node.test):
            if not isinstance(compare, ast.Compare) or not isinstance(compare.ops[0], ast.Eq):
                continue
            sides = [compare.left, *compare.comparators]
            secret = next((s.value for s in sides if isinstance(s, ast.Constant)
                           and isinstance(s.value, str) and _looks_like_key(s.value)), None)
            if secret is None or not any(self.taint_guarded(s) for s in sides):
                continue
            if _body_runs_code(node.body, self.module):
                self.extension.finding(
                    "backdoor.magic-trigger", "backdoor", Severity.HIGH,
                    "Hard-coded value unlocks command or code execution",
                    f"Tool '{self.trace.tool}' compares its input to a fixed random-looking "
                    "string, then runs code. This is a classic backdoor shape.",
                    self.module.file.path, node.lineno, self.module.snippet(node),
                    "Find out why this branch exists before trusting the extension.",
                )

    def report(self, rule, severity, title, node, origin, fix) -> None:
        checked = origin in self.state.validated
        detail = f"Tool '{self.trace.tool}': argument '{origin}' reaches this call"
        detail += f" through {' > '.join(self.state.via)}." if self.state.via else "."
        if checked:
            severity = severity.lowered()
            detail += " A check on this value appears earlier; confirm it is strict enough."
        self.extension.finding(
            rule, "input-validation", severity, title, detail,
            self.module.file.path, node.lineno, self.module.snippet(node), fix,
        )

    def reach(self, capability: str, node: ast.AST) -> None:
        self.extension.capability(
            capability, REACH_TOOL, self.module.file.path, getattr(node, "lineno", 0), self.trace.tool
        )

    def higher_order(self, node: ast.Call, name: str) -> ast.Call | None:
        """Rewrite calls that hand a function to something else, like map(os.system, items)."""
        args = node.args
        keywords = {k.arg: k.value for k in node.keywords if k.arg}
        tail = name.rsplit(".", 1)[-1]
        target: ast.expr | None = None
        passed: list[ast.expr] = []
        if tail in {"map", "imap", "starmap", "apply", "apply_async", "submit", "to_thread"} and args:
            if tail != "map" or len(args) >= 2:
                target, passed = args[0], list(args[1:])
        elif tail in {"Thread", "Process"} and "target" in keywords:
            target = keywords["target"]
            passed = [keywords["args"]] if "args" in keywords else []
        elif tail == "run_in_executor" and len(args) >= 2:
            target, passed = args[1], list(args[2:])
        elif isinstance(node.func, ast.Call) and self.module.resolve(node.func.func) in PARTIAL:
            if node.func.args:
                target, passed = node.func.args[0], [*node.func.args[1:], *args]
        elif isinstance(node.func, ast.Name):
            bound = self.module.assigned.get(node.func.id)
            if isinstance(bound, ast.Call) and self.module.resolve(bound.func) in PARTIAL and bound.args:
                target, passed = bound.args[0], [*bound.args[1:], *args]
        if target is None or not self.module.resolve(target):
            return None
        return ast.copy_location(ast.Call(func=target, args=passed, keywords=[]), node)

    def lambda_call(self, node: ast.Call) -> bool:
        callee = node.func
        if isinstance(callee, ast.Name):
            callee = self.module.assigned.get(callee.id, callee)
        if not isinstance(callee, ast.Lambda):
            return False
        if id(callee) not in self.lambdas:
            self.lambdas.add(id(callee))
            for parameter, arg in zip(callee.args.args, node.args):
                self.state.tainted.pop(parameter.arg, None)
                origin = self.taint(arg)
                if origin:
                    self.state.tainted[parameter.arg] = origin
            self.scan(callee.body)
        return True

    def check_call(self, node: ast.Call) -> None:
        self.trace.project.charge()
        if self.lambda_call(node):
            return
        name = self.module.resolve(node.func)
        rewritten = self.higher_order(node, name)
        if rewritten is not None:
            self.check_call(rewritten)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        self.track_mutation(node, method)
        if name in SHELL_CALLS:
            self.command_sink(node, shell=True)
        elif name in SPAWN_CALLS or name in POSITIONAL_EXEC:
            self.command_sink(node, shell=self.shell_flag(node), positional=name in POSITIONAL_EXEC)
        elif name in CODE_CALLS:
            self.reach(DYNAMIC, node)
            origin = self.taint(node.args[0]) if node.args else None
            if origin:
                self.report("input.code-injection", Severity.CRITICAL,
                            "Tool argument is run as code", node, origin,
                            "Never evaluate tool input. Parse it into a fixed set of operations.")
        elif name in DESERIALIZE_CALLS:
            origin = self.first_taint(node)
            if origin:
                self.report("input.unsafe-deserialization", Severity.HIGH,
                            "Tool argument is deserialized unsafely", node, origin,
                            "Use a data-only format such as JSON.")
        elif name == "yaml.load" and not _safe_yaml(node):
            origin = self.first_taint(node)
            if origin:
                self.report("input.unsafe-deserialization", Severity.HIGH,
                            "Tool argument is parsed with unsafe YAML loading", node, origin,
                            "Use yaml.safe_load.")
        elif name in TEMPLATE_CALLS or method == "from_string":
            origin = self.first_taint(node)
            if origin:
                self.report("input.template-injection", Severity.HIGH,
                            "Tool argument is compiled as a template", node, origin,
                            "Pass values into a fixed template instead.")
        elif name in {"open", "io.open", "codecs.open"}:
            self.file_sink(node, _open_writes(node))
        elif name in READ_CALLS:
            self.file_sink(node, False)
        elif name in WRITE_CALLS:
            self.file_sink(node, True)
        elif method in READ_METHODS or method in WRITE_METHODS:
            self.reach(FS_WRITE if method in WRITE_METHODS else FS_READ, node)
            origin = self.taint(node.func.value)
            if origin:
                self.path_finding(node, origin, method in WRITE_METHODS)
        elif _is_net_call(name, node):
            self.reach(NET, node)
            origin = self.first_taint(node) or self.keyword_taint(node, "url")
            if origin:
                self.extension.capability(UNTRUSTED, REACH_TOOL, self.module.file.path, node.lineno,
                                          f"{self.trace.tool} fetches a caller-chosen URL")
                self.report("input.ssrf", Severity.MEDIUM,
                            "Tool argument chooses which URL is requested", node, origin,
                            "Allow only expected hosts and block private addresses.")
        elif method in SQL_METHODS and _sql_like(node):
            origin = self.taint(node.args[0])
            if origin:
                self.report("input.sql-injection", Severity.HIGH,
                            "Tool argument is built into a SQL statement", node, origin,
                            "Pass values as bound parameters.")
        target = self.local_target(node, name)
        if target is not None:
            self.follow(node, target)

    def track_mutation(self, node: ast.Call, method: str) -> None:
        """Follow values stored into containers or files, such as parts.append(cmd)."""
        if not method or not node.args:
            return
        receiver = node.func.value
        if method in MUTATORS and isinstance(receiver, ast.Name):
            origin = next(filter(None, (self.taint(arg) for arg in node.args)), None)
            if origin:
                self.state.tainted[receiver.id] = origin
        elif method in {"write", "write_text", "writelines"}:
            origin = self.taint(node.args[0])
            path = self.written_path(receiver)
            if origin and path:
                self.trace.written[path] = origin

    def written_path(self, receiver: ast.expr) -> str:
        if isinstance(receiver, ast.Name):
            receiver = self.state.handles.get(receiver.id, receiver)
        if isinstance(receiver, ast.Call) and receiver.args:
            value = self.module.evaluate(receiver.args[0])
            return value if isinstance(value, str) else ""
        return ""

    def first_taint(self, node: ast.Call) -> str | None:
        return self.taint(node.args[0]) if node.args else None

    def keyword_taint(self, node: ast.Call, key: str) -> str | None:
        return next((self.taint(k.value) for k in node.keywords if k.arg == key), None)

    def shell_flag(self, node: ast.Call) -> bool:
        for keyword in node.keywords:
            if keyword.arg == "shell":
                return not (isinstance(keyword.value, ast.Constant) and not keyword.value.value)
            if keyword.arg is None:
                table = keyword.value
                if isinstance(table, ast.Name):
                    table = self.module.assigned.get(table.id, table)
                if isinstance(table, ast.Dict):
                    for key, value in zip(table.keys, table.values):
                        if isinstance(key, ast.Constant) and key.value == "shell":
                            return not (isinstance(value, ast.Constant) and not value.value)
        return False

    def runs_inline(self, items: list[ast.expr]) -> bool:
        """True for ["sh", "-c", value]: a list, but a shell still parses the value."""
        if len(items) < 3:
            return False
        for item in items[:2]:  # os.spawnlp takes a mode before the program
            program = "python" if self.module.resolve(item) == "sys.executable" else self.module.evaluate(item)
            if isinstance(program, str) and program.replace("\\", "/").rsplit("/", 1)[-1].lower() in INTERPRETERS:
                flags = (self.module.evaluate(entry) for entry in items[1:])
                return any(isinstance(flag, str) and flag.lower() in INLINE_FLAGS for flag in flags)
        return False

    def command_sink(self, node: ast.Call, shell: bool, positional: bool = False) -> None:
        self.reach(EXEC, node)
        if positional:
            command: ast.expr | None = ast.List(elts=list(node.args))
        else:
            command = node.args[0] if node.args else next(
                (k.value for k in node.keywords if k.arg == "args"), None
            )
        if command is None:
            return
        origin = self.taint(command)
        if not origin:
            self.runs_written_file(node, command)
            return
        fix = "Use a fixed program with an argument list, and validate each argument."
        items = list(command.elts) if isinstance(command, (ast.List, ast.Tuple)) else []
        if shell:
            self.report("input.command-injection", Severity.CRITICAL,
                        "Tool argument reaches a shell command", node, origin, fix)
        elif self.runs_inline(items):
            self.report("input.command-injection", Severity.CRITICAL,
                        "Tool argument is run by a shell or interpreter", node, origin, fix)
        elif items and not self.taint(items[0]):
            self.report("input.argument-injection", Severity.MEDIUM,
                        "Tool argument is passed to a program without validation", node, origin,
                        "Validate the value and add '--' before it so it cannot act as a flag.")
        else:
            self.report("input.command-injection", Severity.HIGH,
                        "Tool argument chooses which program runs", node, origin, fix)

    def runs_written_file(self, node: ast.Call, command: ast.expr) -> None:
        """Catch input saved to a file that a fixed command then runs."""
        if not self.trace.written:
            return
        value = self.module.evaluate(command)
        text = " ".join(str(item) for item in value) if isinstance(value, list) else value
        if isinstance(text, str):
            for path, origin in self.trace.written.items():
                if path in text:
                    self.report("input.command-injection", Severity.CRITICAL,
                                "Tool argument is saved to a script that is then run", node, origin,
                                "Do not build scripts from tool input.")

    def file_sink(self, node: ast.Call, writes: bool) -> None:
        self.reach(FS_WRITE if writes else FS_READ, node)
        if any(isinstance(part, ast.Constant) and isinstance(part.value, str) and SENSITIVE_PATH.search(part.value[:4096])
               for arg in node.args for part in ast.walk(arg)):
            self.reach(SECRETS, node)
        origin = self.first_taint(node)
        if origin:
            self.path_finding(node, origin, writes)

    def path_finding(self, node: ast.Call, origin: str, writes: bool) -> None:
        action = "write or delete" if writes else "read"
        if self.module.resolve(node.func) in COPY_CALLS:
            action = "copy or move"
        self.report("input.path-traversal", Severity.HIGH if writes else Severity.MEDIUM,
                    f"Tool argument chooses which file to {action}", node, origin,
                    "Resolve the path and confirm it stays inside an allowed folder.")

    def follow(self, node: ast.Call, target) -> Summary | None:
        """Enter a helper from this extension, carrying taint into its parameters."""
        module, function = target
        parameters = [a.arg for a in [*function.args.posonlyargs, *function.args.args]]
        if parameters and parameters[0] in {"self", "cls"}:
            parameters = parameters[1:]
        tainted: dict[str, str] = {}
        for position, arg in enumerate(node.args):
            origin = self.taint(arg)
            if origin and position < len(parameters):
                tainted[parameters[position]] = origin
        for keyword in node.keywords:
            origin = self.taint(keyword.value)
            if origin and keyword.arg:
                tainted[keyword.arg] = origin
        state = State(tainted, set(self.state.validated), via=(*self.state.via, function.name))
        return self.trace.enter(module, function, state, self.depth + 1)

    def local_target(self, node: ast.Call, name: str):
        project = self.trace.project
        func = node.func
        if isinstance(func, ast.Call):  # Runner()(value) goes to __call__
            owner = self.class_of(func)
            return project.find_method(owner, "__call__", self.module) if owner else None
        if isinstance(func, ast.Name):
            if func.id in self.state.instances:
                return project.find_method(self.state.instances[func.id], "__call__", self.module)
            simple = name.rsplit(".", 1)[-1]
            if project.is_class(simple, self.module):
                return project.find_method(simple, "__init__", self.module)
            return project.find(simple, self.module)
        if isinstance(func, ast.Attribute):
            base = dotted(func.value) or ""
            if base in {"self", "cls"}:
                return project.find(func.attr, self.module)
            if project.is_class(base, self.module):  # Tools.go(x), a static or class method
                return project.find_method(base, func.attr, self.module)
            owner = ""
            if isinstance(func.value, ast.Name):
                owner = self.state.instances.get(func.value.id, "")
            elif isinstance(func.value, ast.Call):
                owner = self.class_of(func.value)
            if owner:
                return project.find_method(owner, func.attr, self.module)
            root = self.module.aliases.get(base.split(".")[0], "")
            if root.startswith("."):
                return project.find(func.attr, self.module)
        return None


class BehaviorWalker(Walker):
    """Track credentials toward the network, and downloaded data toward code execution.

    Same flow machinery as tool tracing, with different sources and sinks. It runs on
    all code because these behaviors matter whether or not a tool reaches them. Encoding
    a secret does not make it safe to send, so sanitizers do not clear anything here.
    """

    honors_sanitizers = False

    def function(self, node) -> None:
        self.trace.enter(self.module, node, State({}, set()), self.depth)

    def magic_trigger(self, node: ast.If) -> None:
        pass

    def taint(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant):
            sensitive = isinstance(node.value, str) and CREDENTIAL_FILE.search(node.value[:4096])
            return CREDENTIALS if sensitive else None
        if isinstance(node, ast.Subscript) and self.module.resolve(node.value) == "os.environ":
            return self.one_variable(node.slice)  # most variables are harmless to read
        if isinstance(node, ast.Attribute):
            name = self.module.resolve(node)
            if name == "os.environ":
                return ENVIRONMENT
            if name == "sys.stdin":
                return STANDARD_INPUT
        return super().taint(node)

    def one_variable(self, key: ast.expr | None) -> str | None:
        value = self.module.evaluate(key)
        return SECRET_VARIABLE if isinstance(value, str) and is_secret_name(value) else None

    def call_taint(self, node: ast.Call) -> str | None:
        name = self.module.resolve(node.func)
        if name == "os.getenv" or (isinstance(node.func, ast.Attribute) and node.func.attr == "get"
                                   and self.module.resolve(node.func.value) == "os.environ"):
            return self.one_variable(node.args[0] if node.args else None)
        if name.startswith("sys.stdin."):
            return STANDARD_INPUT
        if _is_net_call(name, node):
            return DOWNLOAD
        return super().call_taint(node)

    def check_call(self, node: ast.Call) -> None:
        self.trace.project.charge()
        if self.lambda_call(node):
            return
        name = self.module.resolve(node.func)
        rewritten = self.higher_order(node, name)
        if rewritten is not None:
            self.check_call(rewritten)
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name in CODE_CALLS or name in COMMAND_CALLS:
            if node.args and self.taint(node.args[0]) == DOWNLOAD:
                self.extension.finding(
                    "backdoor.remote-code", "backdoor", Severity.CRITICAL,
                    f"Code downloaded from the network is passed to {name}",
                    "The code that runs can change at any time, and this scan never sees it.",
                    self.module.file.path, node.lineno, self.module.snippet(node),
                )
        elif _is_net_call(name, node) or method in SEND_METHODS or name in DNS_CALLS:
            body = [k.value for k in node.keywords if k.arg not in SIGNED_REQUEST_FIELDS]
            for index, arg in enumerate([*node.args, *body]):
                origin = self.taint(arg)
                if origin == SECRET_VARIABLE and index == 0:
                    continue  # some APIs, such as Telegram's, put the token in their own URL
                if origin in EXFIL_DETAIL:
                    self.extension.finding(
                        "backdoor.exfiltration", "backdoor", EXFIL_SEVERITY[origin],
                        f"Traced: {origin} sent over the network",
                        EXFIL_DETAIL[origin], self.module.file.path, node.lineno,
                        self.module.snippet(node),
                        "Find out what this sends and why before trusting the extension.",
                    )
                    break
        target = self.local_target(node, name)
        if target is not None:
            self.follow(node, target)


def _is_remote_result(node: ast.expr) -> bool:
    """True for `await client.fetch(id)`: the result is what the API returned,
    not the caller's argument. Awaited helpers that pass a value through still count."""
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
        return False
    return (dotted(node.func.value) or "") not in {"self", "cls"} and node.func.attr not in AWAIT_PASS_THROUGH


def _is_context(arg: ast.arg) -> bool:
    annotation = dotted(arg.annotation) if arg.annotation is not None else ""
    return arg.arg in {"ctx", "context"} or (annotation or "").rsplit(".", 1)[-1] == "Context"


def _safe_annotation(node: ast.expr | None) -> bool:
    """True for types the MCP SDK enforces, such as int or Literal choices."""
    if node is None:
        return False
    name = dotted(node)
    if name:
        return name.rsplit(".", 1)[-1] in SAFE_ANNOTATIONS
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        sides = (node.left, node.right)
        return all(_safe_annotation(s) or (isinstance(s, ast.Constant) and s.value is None) for s in sides)
    if isinstance(node, ast.Subscript):
        base = (dotted(node.value) or "").rsplit(".", 1)[-1]
        if base == "Literal":
            return True
        if base in {"Optional", "Annotated"}:
            inner = node.slice.elts[0] if isinstance(node.slice, ast.Tuple) else node.slice
            return _safe_annotation(inner)
    return False


def _has_pattern(node: ast.expr) -> bool:
    return any(isinstance(n, ast.keyword) and n.arg in {"pattern", "regex"} for n in ast.walk(node))


def _safe_yaml(node: ast.Call) -> bool:
    for keyword in node.keywords:
        if keyword.arg == "Loader" and "Safe" in (dotted(keyword.value) or ""):
            return True
    return len(node.args) > 1 and "Safe" in (dotted(node.args[1]) or "")


def _open_writes(node: ast.Call) -> bool:
    mode = node.args[1] if len(node.args) > 1 else next(
        (k.value for k in node.keywords if k.arg == "mode"), None
    )
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(c in mode.value for c in "wax+")


def _is_net_call(name: str, node: ast.Call) -> bool:
    if name in NET_CALLS:
        return True
    head, _, tail = name.partition(".")
    if head in NET_MODULES and tail in HTTP_VERBS:
        return True
    if isinstance(node.func, ast.Attribute) and node.func.attr in HTTP_VERBS:
        receiver = (dotted(node.func.value) or "").lower()
        return any(hint in receiver for hint in HTTP_RECEIVER_HINTS)
    return False


def _sql_like(node: ast.Call) -> bool:
    if not node.args:
        return False
    if node.func.attr == "executescript":
        return True
    first = node.args[0]
    if isinstance(first, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(first, ast.Call) and isinstance(first.func, ast.Attribute) and first.func.attr == "format":
        return True
    receiver = (dotted(node.func.value) or "").lower().rsplit(".", 1)[-1]
    return any(hint in receiver for hint in SQL_RECEIVER_HINTS)


def _looks_like_key(value: str) -> bool:
    return len(value) >= 12 and " " not in value and entropy(value) >= 3.0


def _body_runs_code(body: list[ast.stmt], module: Module) -> bool:
    for statement in body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Call):
                name = module.resolve(node.func)
                if name in COMMAND_CALLS or name in CODE_CALLS:
                    return True
    return False


def _file_pass(module: Module, extension: Extension) -> None:
    """Checks that apply to the whole file, whether or not a tool reaches the code."""
    path = module.file.path
    env_arguments: set[int] = set()
    decoded: set[str] = set()
    for node in ast.walk(module.tree):
        if isinstance(node, ast.keyword) and node.arg == "env":
            env_arguments.update(id(n) for n in ast.walk(node.value))
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            if module.resolve(node.value.func) in DECODERS or _decodes(node.value, module):
                decoded.update(t.id for t in node.targets if isinstance(t, ast.Name))

    for node in ast.walk(module.tree):
        if isinstance(node, ast.Call):
            _call_checks(node, module, extension, env_arguments, decoded)
        elif isinstance(node, ast.If):
            _time_trigger(node, module, extension)

    name = path.rsplit("/", 1)[-1]
    if name in {"setup.py", "__init__.py"}:
        _import_time(module, extension, name)


def _decodes(node: ast.Call, module: Module) -> bool:
    return any(
        isinstance(n, ast.Call) and module.resolve(n.func) in DECODERS for n in ast.walk(node)
    )


def _is_disguised(node: ast.AST, module: Module, depth: int = 0) -> bool:
    """True when a value is built in a way that hides it from someone reading the code."""
    line = getattr(node, "lineno", 0)
    if 0 < line <= len(module.lines) and HEX_ESCAPES.search(module.lines[line - 1]):
        return True
    if depth > 4:
        return False
    for part in ast.walk(node):
        if isinstance(part, ast.BinOp) and isinstance(part.op, ast.BitXor):
            return True
        if isinstance(part, ast.Call):
            name = module.resolve(part.func)
            if name in DECODERS or name == "chr":
                return True
            if isinstance(part.func, ast.Attribute) and part.func.attr == "join" and len(part.args) == 1:
                joined = module.evaluate(part.func.value)
                if joined == "" and not isinstance(part.args[0], ast.Name):
                    return True
            if isinstance(part.func, ast.Name):  # a local helper that does the decoding
                helper = module.functions.get(part.func.id) or module.assigned.get(part.func.id)
                if isinstance(helper, ast.Lambda):
                    helper = helper.body
                if isinstance(helper, ast.AST) and _is_disguised(helper, module, depth + 1):
                    return True
        elif isinstance(part, ast.Subscript) and isinstance(part.slice, ast.Slice) and part.slice.step is not None:
            return True
        elif isinstance(part, ast.Name) and isinstance(module.assigned.get(part.id), ast.Call):
            if _is_disguised(module.assigned[part.id], module, depth + 1):
                return True
    return False


def _is_assembled(node: ast.AST, module: Module) -> bool:
    """True when a string is put together rather than written out, like "".join(parts)."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name) and isinstance(module.assigned.get(node.id), ast.Constant):
        return False
    value = module.evaluate(node)
    return isinstance(value, (str, bytes)) and bool(value.strip())


def _constant_command(node: ast.Call, module: Module, extension: Extension) -> None:
    """Read commands written as constants, however they were put together."""
    subject: ast.expr | None = node.args[0] if node.args else None
    value = module.evaluate(ast.List(elts=list(node.args)) if subject is not None else None)
    if isinstance(value, list) and isinstance(subject, (ast.List, ast.Tuple)):
        value = module.evaluate(subject)
    if isinstance(value, list):
        text = " ".join(_as_text(item) for item in _flat(value))
    else:
        text = ""
    if not text.strip():
        return
    path = module.file.path
    if _is_disguised(subject, module):
        extension.finding(
            "backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
            "A disguised command is decoded and run",
            f"Worked out without running it: {clip(text, 200)}",
            path, node.lineno, module.snippet(node),
        )
    shell.scan_command(extension, text, path, node.lineno, REACH_CODE)


def _flat(items: list) -> list:
    out: list = []
    for item in items:
        if isinstance(item, list):
            out.extend(_flat(item))
        else:
            out.append(item)
    return out


def _as_text(value) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _call_checks(node, module, extension, env_arguments, decoded) -> None:
    path = module.file.path
    name = module.resolve(node.func)
    method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
    line = node.lineno
    if (name in COMMAND_CALLS or name in CODE_CALLS) and _hides_name(node.func, module):
        extension.finding(
            "backdoor.dynamic-dispatch", "backdoor", Severity.HIGH,
            f"The name of {name} is computed, which hides the call",
            "Honest code has no need to assemble the name of a function that runs commands.",
            path, line, module.snippet(node),
        )
    if name in COMMAND_CALLS:
        extension.capability(EXEC, REACH_CODE, path, line)
        _constant_command(node, module, extension)
    elif name in CODE_CALLS and name != "compile":
        extension.capability(DYNAMIC, REACH_CODE, path, line)
        _obfuscated_code(node, module, extension, name, decoded)
    elif name in {"open", "io.open", "codecs.open"}:
        extension.capability(FS_WRITE if _open_writes(node) else FS_READ, REACH_CODE, path, line)
    elif name in READ_CALLS or method in READ_METHODS:
        extension.capability(FS_READ, REACH_CODE, path, line)
    elif name in WRITE_CALLS or method in WRITE_METHODS:
        extension.capability(FS_WRITE, REACH_CODE, path, line)
    elif _is_net_call(name, node):
        extension.capability(NET, REACH_CODE, path, line)
        if node.args and _is_disguised(node.args[0], module):
            target = module.evaluate(node.args[0])
            extension.finding(
                "backdoor.obfuscated-code", "backdoor", Severity.HIGH,
                "A network address is disguised",
                f"Worked out without running it: {clip(_as_text(target), 120)}" if isinstance(target, (str, bytes))
                else "The address is computed in a way that hides it.",
                path, line, module.snippet(node),
            )
    if name in DESERIALIZE_CALLS and _decodes(node, module):
        extension.finding(
            "backdoor.obfuscated-code", "backdoor", Severity.HIGH,
            "Encoded data is decoded and unpickled",
            "Unpickling runs code, so this is hidden code execution.",
            path, line, module.snippet(node),
        )
    if name in LOADER_CALLS:
        extension.finding(
            "backdoor.dynamic-loader", "backdoor", Severity.MEDIUM,
            f"{name} builds code at run time",
            "Code made this way cannot be read from the source.",
            path, line, module.snippet(node),
        )

    if name in {"json.dumps", "str", "repr", "dict"} and id(node) not in env_arguments:
        if node.args and module.resolve(node.args[0]) == "os.environ":
            extension.finding(
                "backdoor.env-dump", "backdoor", Severity.MEDIUM,
                "Whole environment is copied into a value",
                "Environment variables usually hold API keys. Check where this value goes.",
                path, line, module.snippet(node),
                "Read only the variables the extension needs.",
            )

    for keyword in node.keywords:
        value = keyword.value
        if keyword.arg == "verify" and isinstance(value, ast.Constant) and value.value is False:
            extension.finding("opsec.tls-disabled", "opsec", Severity.MEDIUM,
                              "TLS certificate checks are turned off",
                              "Traffic can be intercepted without any warning.",
                              path, line, module.snippet(node), "Remove verify=False.")
        if keyword.arg in {"host", "bind", "listen"} and isinstance(value, ast.Constant) and value.value in {"0.0.0.0", "::"}:
            extension.finding("opsec.bind-all", "opsec", Severity.MEDIUM,
                              "Server listens on every network interface",
                              "Other devices on the network may be able to reach it.",
                              path, line, module.snippet(node), "Bind to 127.0.0.1.")
    if name == "ssl._create_unverified_context":
        extension.finding("opsec.tls-disabled", "opsec", Severity.MEDIUM,
                          "TLS certificate checks are turned off",
                          "Traffic can be intercepted without any warning.",
                          path, line, module.snippet(node), "Use the default SSL context.")

    root = name.split(".", 1)[0]
    if name in LOG_CALLS or (root in LOG_ROOTS and method in {"debug", "info", "warning", "error", "critical", "exception", "log"}):
        for part in [*node.args, *(k.value for k in node.keywords)]:
            for inner in ast.walk(part):
                label = inner.id if isinstance(inner, ast.Name) else inner.attr if isinstance(inner, ast.Attribute) else ""
                if label and is_secret_name(label):
                    extension.finding("opsec.secret-in-log", "opsec", Severity.MEDIUM,
                                      f"Logging call includes '{label}'",
                                      "Logs are often copied into bug reports and support tickets.",
                                      path, line, module.snippet(node), "Remove the value from the log line.")
                    return


def _hides_name(node: ast.AST, module: Module) -> bool:
    """True when the function being called is named by a computed string."""
    for part in ast.walk(node):
        if isinstance(part, ast.Call) and len(part.args) >= 1:
            called = module.resolve(part.func)
            if called == "getattr" and len(part.args) >= 2 and not isinstance(part.args[1], ast.Constant):
                return True
            if called in {"__import__", "importlib.import_module"} and not isinstance(part.args[0], ast.Constant):
                return True
        elif isinstance(part, ast.Subscript) and not isinstance(part.slice, ast.Constant):
            return True
    return False


def _obfuscated_code(node, module, extension, name, decoded) -> None:
    path = module.file.path
    if node.args and any(isinstance(n, ast.Call) and module.resolve(n.func) in {"open", "io.open"} for n in ast.walk(node.args[0])):
        extension.finding(
            "backdoor.exec-data-file", "backdoor", Severity.MEDIUM,
            f"Code from another file is passed to {name}",
            "Whatever is in that file runs here, and it may not look like code to a reviewer.",
            path, node.lineno, module.snippet(node),
        )
    if node.args and (_is_disguised(node.args[0], module) or _is_assembled(node.args[0], module)):
        value = module.evaluate(node.args[0])
        text = _as_text(value) if isinstance(value, (str, bytes)) else ""
        extension.finding(
            "backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
            f"Encoded data is decoded and passed to {name}",
            f"Worked out without running it: {clip(text, 200)}" if text else "Honest code rarely hides what it runs.",
            path, node.lineno, module.snippet(node),
        )
        return
    for inner in ast.walk(node):
        if inner is node or not isinstance(inner, (ast.Call, ast.Name)):
            continue
        fetched = isinstance(inner, ast.Call) and _is_net_call(module.resolve(inner.func), inner)
        hidden = (isinstance(inner, ast.Call) and module.resolve(inner.func) in DECODERS) or (
            isinstance(inner, ast.Name) and inner.id in decoded
        )
        if fetched:
            extension.finding(
                "backdoor.remote-code", "backdoor", Severity.CRITICAL,
                f"Code downloaded from the network is passed to {name}",
                "The code that runs can change at any time, and this scan never sees it.",
                path, node.lineno, module.snippet(node),
            )
            return
        if hidden:
            extension.finding(
                "backdoor.obfuscated-code", "backdoor", Severity.CRITICAL,
                f"Encoded data is decoded and passed to {name}",
                "Honest code rarely hides what it runs.",
                path, node.lineno, module.snippet(node),
            )
            return


def _time_trigger(node: ast.If, module: Module, extension: Extension) -> None:
    uses_clock = any(
        isinstance(n, ast.Call) and module.resolve(n.func) in CLOCK_CALLS for n in ast.walk(node.test)
    )
    if uses_clock and any(isinstance(n, ast.Compare) for n in ast.walk(node.test)):
        if _body_runs_code(node.body, module):
            extension.finding(
                "backdoor.time-trigger", "backdoor", Severity.MEDIUM,
                "Command or code execution depends on the date or time",
                "Delayed behavior can stay hidden during review and testing.",
                module.file.path, node.lineno, module.snippet(node),
            )


def _import_time(module: Module, extension: Extension, name: str) -> None:
    for statement in module.tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue
            call = module.resolve(node.func)
            if call in COMMAND_CALLS or _is_net_call(call, node):
                extension.finding(
                    "backdoor.install-time-code", "backdoor",
                    Severity.HIGH if name == "setup.py" else Severity.MEDIUM,
                    f"{name} runs a command or network call when it loads",
                    "This runs during install or import, before any tool is called.",
                    module.file.path, node.lineno, module.snippet(node),
                )
                return
