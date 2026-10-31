"""Data types shared by the loaders, analyzers and reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    def lowered(self) -> "Severity":
        return Severity(max(self - 1, Severity.INFO))

    def raised(self) -> "Severity":
        return Severity(min(self + 1, Severity.CRITICAL))


# Capabilities: what an extension is able to do.
EXEC = "exec"
FS_READ = "fs_read"
FS_WRITE = "fs_write"
NET = "net_out"
SECRETS = "secrets"
DYNAMIC = "dynamic_code"
PERSIST = "persistence"
AGENT_CONFIG = "agent_config"
UNTRUSTED = "untrusted_input"

CAPABILITY_LABELS = {
    EXEC: "run commands",
    FS_READ: "read files",
    FS_WRITE: "write files",
    NET: "send network traffic",
    SECRETS: "touch credentials",
    DYNAMIC: "run dynamic code",
    PERSIST: "persist on the machine",
    AGENT_CONFIG: "change Claude's config",
    UNTRUSTED: "bring in outside content",
}

# Reach: how Claude or the host gets to that capability.
REACH_TOOL = "tool"  # called from an MCP tool handler, so Claude can trigger it
REACH_HOOK = "hook"  # runs on a Claude Code event
REACH_CODE = "code"  # present in the code, but no path from a tool was traced
REACH_DECLARED = "declared"  # stated in configuration or a known package
REACH_INFERRED = "inferred"  # guessed from names; weakest evidence

MODEL_REACHABLE = {REACH_TOOL, REACH_DECLARED, REACH_INFERRED}


@dataclass(frozen=True)
class Capability:
    name: str
    reach: str
    file: str = ""
    line: int = 0
    note: str = ""


@dataclass
class Finding:
    rule: str
    category: str  # input-validation | opsec | backdoor | chain | update
    severity: Severity
    title: str
    detail: str = ""
    file: str = ""
    line: int = 0
    snippet: str = ""
    fix: str = ""
    extension: str = ""


@dataclass(frozen=True)
class Gap:
    """Something the scan could not check. Always reported next to the findings."""

    subject: str
    reason: str


@dataclass
class PackageFile:
    path: str
    data: bytes

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace").removeprefix("\ufeff")

    @property
    def suffix(self) -> str:
        name = self.path.rsplit("/", 1)[-1]
        return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


@dataclass
class ServerDecl:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str = ""
    transport: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    origin: str = ""


@dataclass
class HookDecl:
    event: str
    matcher: str = ""
    type: str = "command"
    command: str = ""
    args: list[str] = field(default_factory=list)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    prompt: str = ""
    condition: str = ""
    allowed_env: list[str] = field(default_factory=list)
    origin: str = ""


@dataclass
class ToolDecl:
    name: str
    description: str = ""
    source: str = ""  # "manifest" or "code"
    file: str = ""
    line: int = 0


@dataclass
class Doc:
    """Markdown that Claude reads as instructions."""

    path: str
    kind: str  # skill | command | agent | prompt
    text: str
    frontmatter: dict = field(default_factory=dict)
    body_line: int = 1


@dataclass
class Extension:
    name: str
    kind: str  # mcpb | plugin | skill | mcp-config | settings | source
    location: str
    version: str = ""
    files: list[PackageFile] = field(default_factory=list)
    servers: list[ServerDecl] = field(default_factory=list)
    hooks: list[HookDecl] = field(default_factory=list)
    tools: list[ToolDecl] = field(default_factory=list)
    docs: list[Doc] = field(default_factory=list)
    manifest: dict = field(default_factory=dict)
    settings: dict = field(default_factory=dict)
    binaries: list[str] = field(default_factory=list)
    binary_data: dict[str, bytes] = field(default_factory=dict, repr=False)
    vendored: dict[str, dict] = field(default_factory=dict)
    vendored_files: int = 0
    assets_skipped: int = 0
    hosts: set[str] = field(default_factory=set)
    dependencies: dict[str, str] = field(default_factory=dict)
    install_scripts: dict[str, str] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    capabilities: set[Capability] = field(default_factory=set)
    gaps: list[Gap] = field(default_factory=list)
    file_caps: dict[str, set[str]] = field(default_factory=dict)
    _seen: set = field(default_factory=set, repr=False)
    _seen_places: set = field(default_factory=set, repr=False)
    _seen_gaps: set = field(default_factory=set, repr=False)
    _seen_tools: set = field(default_factory=set, repr=False)
    _index: dict = field(default_factory=dict, repr=False)

    def finding(
        self,
        rule: str,
        category: str,
        severity: Severity,
        title: str,
        detail: str = "",
        file: str = "",
        line: int = 0,
        snippet: str = "",
        fix: str = "",
    ) -> None:
        key = (rule, file, line, title)
        if key in self._seen:
            return
        self._seen.add(key)
        self._seen_places.add((rule, file, line))
        self.findings.append(
            Finding(rule, category, severity, title, detail, file, line, snippet, fix, self.name)
        )

    def already(self, rule: str, file: str, line: int) -> bool:
        return (rule, file, line) in self._seen_places

    def capability(
        self, name: str, reach: str, file: str = "", line: int = 0, note: str = ""
    ) -> None:
        self.capabilities.add(Capability(name, reach, file, line, note))
        if file:
            self.file_caps.setdefault(file, set()).add(name)

    def gap(self, subject: str, reason: str) -> None:
        item = Gap(subject, reason)
        if item not in self._seen_gaps:
            self._seen_gaps.add(item)
            self.gaps.append(item)

    def clear_gap(self, subject: str) -> None:
        """Drop a gap that has since been closed, such as a package that is now read."""
        self.gaps = [item for item in self.gaps if item.subject != subject]
        self._seen_gaps = {item for item in self._seen_gaps if item.subject != subject}

    def code_tool(self, name: str, description: str, file: str, line: int) -> None:
        """Record a tool found in source code, once per name."""
        if name not in self._seen_tools:
            self._seen_tools.add(name)
            self.tools.append(ToolDecl(name, description, "code", file, line))

    def has(self, name: str, reaches: set[str] | None = None) -> bool:
        return any(
            c.name == name and (reaches is None or c.reach in reaches)
            for c in self.capabilities
        )

    def file(self, path: str) -> PackageFile | None:
        if len(self._index) != len(self.files):
            self._index = {f.path: f for f in self.files}
        return self._index.get(path)
