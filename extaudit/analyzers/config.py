"""Check declared MCP servers, hooks, manifests and Claude Code settings."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..model import (
    EXEC,
    FS_READ,
    FS_WRITE,
    NET,
    REACH_CODE,
    REACH_DECLARED,
    REACH_HOOK,
    REACH_INFERRED,
    REACH_TOOL,
    UNTRUSTED,
    Extension,
    HookDecl,
    ServerDecl,
    Severity,
)
from ..patterns import SECRET_PATTERNS, clip, is_secret_name, looks_random, words
from . import documents, shell

RUNNERS = {"npx", "bunx", "pnpx", "uvx", "pipx"}
ENV_REFERENCE = re.compile(r"^\$\{[^}]+\}$|^\$[A-Z_]+$|^\{\{[^}]+\}\}$")
URL_SECRET = re.compile(r"(?i)[?&](?:api[_-]?key|token|access_token|auth|secret|key)=([^&\s]{8,})")
ROOT_REFERENCE = re.compile(r"\$\{?(?:CLAUDE_PLUGIN_ROOT|CLAUDE_SKILL_DIR)\}?[/\\]([^\s\"']+)")
SHELLS = {"bash", "sh", "zsh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"}
LOCALHOST = {"localhost", "127.0.0.1", "::1", "[::1]"}
TOOL_EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "PostToolBatch", "PermissionRequest"}
PROMPT_EVENTS = {"UserPromptSubmit", "UserPromptExpansion"}
AUTOMATIC_EVENTS = {"SessionStart", "Setup", "InstructionsLoaded"}
CONTEXT_EVENTS = {"SessionStart", "UserPromptSubmit", "UserPromptExpansion"}
COMMON_COMMANDS = {
    "git", "curl", "wget", "ssh", "scp", "node", "npm", "npx", "python", "python3", "pip", "pip3",
    "sudo", "ls", "cat", "bash", "sh", "gh", "docker", "make", "rm", "cp", "mv", "cargo", "go",
}

# Words that mean an extension pulls in text written by other people.
OUTSIDE_CONTENT = {
    "gmail", "email", "emails", "mail", "mailbox", "inbox", "outlook", "calendar", "gcal",
    "slack", "discord", "telegram", "whatsapp", "imessage", "sms", "twitter", "reddit",
    "browser", "browse", "scrape", "scraper", "crawl", "crawler", "webpage", "website",
    "playwright", "puppeteer", "rss", "github", "gitlab", "jira", "linear", "notion",
    "confluence", "asana", "trello", "zendesk", "intercom", "hubspot", "salesforce",
    "gdrive", "dropbox", "onedrive", "sharepoint",
}
FETCH_VERBS = {"fetch", "get", "read", "open", "load", "download"}
FETCH_NOUNS = {"url", "page", "webpage", "website", "link"}

# Well-known packages whose abilities are public, used when no source is available.
KNOWN_PACKAGES = {
    "server-filesystem": (FS_READ, FS_WRITE),
    "server-puppeteer": (NET, UNTRUSTED),
    "server-fetch": (NET, UNTRUSTED),
    "desktop-commander": (EXEC, FS_READ, FS_WRITE),
    "mcp-server-commands": (EXEC,),
    "mcp-shell": (EXEC,),
    "mcp-server-shell": (EXEC,),
}
SHELLISH_NAMES = {"shell", "terminal", "exec", "bash", "powershell", "ssh", "commander"}


def analyze(extension: Extension) -> None:
    for server in extension.servers:
        _server(extension, server)
    for hook in extension.hooks:
        _hook(extension, hook)
    if extension.kind == "mcpb":
        _manifest(extension)
    if extension.kind == "plugin":
        _plugin(extension)
    if extension.settings:
        _settings(extension)
    _undeclared_tools(extension)
    _infer_outside_content(extension)
    _coverage(extension)


def _server(extension: Extension, server: ServerDecl) -> None:
    if server.url:
        _remote_server(extension, server)
    if server.command:
        _local_server(extension, server)
    for label, values in (("env", server.env), ("headers", server.headers)):
        for key, value in values.items():
            if _is_plaintext_secret(key, value):
                extension.finding(
                    "opsec.plaintext-secret", "opsec", Severity.HIGH,
                    f"Server '{clip(server.name, 40)}' stores {clip(key, 40)} in plain text",
                    "Config files get backed up, synced and shared. The value is not shown here.",
                    server.origin, fix="Use an environment reference such as ${API_KEY}.",
                )
    packages = " ".join([server.command, *server.args]).lower()
    for package, capabilities in KNOWN_PACKAGES.items():
        if package in packages:
            for capability in capabilities:
                extension.capability(capability, REACH_DECLARED, server.origin, 0, f"known package {package}")
    if SHELLISH_NAMES & set(words(server.name)):
        extension.capability(EXEC, REACH_INFERRED, server.origin, 0, f"server is named {clip(server.name, 40)}")


def _remote_server(extension: Extension, server: ServerDecl) -> None:
    parts = urlsplit(server.url)
    host = parts.hostname or server.url
    extension.capability(NET, REACH_DECLARED, server.origin, 0, f"hosted server at {host}")
    extension.hosts.add(host.lower())
    if host in LOCALHOST:
        return
    extension.gap(f"server {server.name}", f"hosted at {host}; its code cannot be read and can change at any time")
    if parts.scheme in {"http", "ws"}:
        extension.finding(
            "opsec.insecure-transport", "opsec", Severity.HIGH,
            f"Server '{clip(server.name, 40)}' connects without encryption",
            "Tool calls and any tokens can be read or changed in transit.",
            server.origin, fix="Use https.",
        )
    match = URL_SECRET.search(server.url)
    if match and not ENV_REFERENCE.match(match.group(1)):
        extension.finding(
            "opsec.plaintext-secret", "opsec", Severity.HIGH,
            f"Server '{clip(server.name, 40)}' has a credential in its URL",
            "URLs end up in logs. The value is not shown here.",
            server.origin, fix="Send the credential in a header.",
        )


def _local_server(extension: Extension, server: ServerDecl) -> None:
    program = server.command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    joined = " ".join([server.command, *server.args])
    # Starting a server runs a program, but Claude does not choose what it runs.
    extension.capability(EXEC, REACH_CODE, server.origin, 0, f"starts {clip(program, 30)}")
    shell.scan_command(extension, joined, server.origin, 0, REACH_DECLARED)
    if program in RUNNERS or (program in {"pnpm", "yarn", "uv", "pipx"} and {"dlx", "run", "tool"} & set(server.args[:2])):
        _runner(extension, server, program)
    elif program == "docker":
        _docker(extension, server)
    else:
        if extension.kind == "mcp-config":
            extension.gap(
                f"server {server.name}",
                f"config only says to start {clip(program, 40)}; scan that program's folder directly",
            )
        if program in SHELLS and any(a in {"-c", "/c", "-Command", "-command"} for a in server.args):
            extension.finding(
                "opsec.shell-launcher", "opsec", Severity.MEDIUM,
                f"Server '{clip(server.name, 40)}' is started through a shell command",
                "A shell one-liner can do anything, and it is easy to overlook.",
                server.origin, snippet=clip(joined),
            )


def _runner(extension: Extension, server: ServerDecl, program: str) -> None:
    package = _package_argument(server.args)
    label = clip(package or server.name, 60)
    extension.gap(f"server {server.name}", f"{label} is downloaded when it starts, so its code was not scanned")
    if not package or _pinned(package):
        return
    extension.finding(
        "supply.unpinned-runner", "opsec", Severity.MEDIUM,
        f"Server '{clip(server.name, 40)}' runs the newest version of {label}",
        "A hijacked release would run on your machine at the next start.",
        server.origin, snippet=clip(" ".join([program, *server.args])),
        fix="Pin an exact version, such as name@1.2.3.",
    )


def _package_argument(args: list[str]) -> str:
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in {"-p", "--package", "--from", "--with"}:
            skip = True
            continue
        if arg in {"dlx", "run", "tool", "--yes", "-y"} or arg.startswith("-"):
            continue
        return arg
    return ""


def _pinned(package: str) -> bool:
    if "==" in package:
        return True
    version = package[1:].rsplit("@", 1) if package.startswith("@") else package.rsplit("@", 1)
    return len(version) == 2 and bool(re.match(r"^\d+\.\d+", version[1]))


def _docker(extension: Extension, server: ServerDecl) -> None:
    args = " ".join(server.args)
    extension.gap(f"server {server.name}", "runs in a container image, which was not scanned")
    if re.search(r"--privileged|--network[ =]host|--pid[ =]host|-v\s+/:|/var/run/docker\.sock", args):
        extension.finding(
            "opsec.docker-escape", "opsec", Severity.HIGH,
            f"Server '{clip(server.name, 40)}' weakens container isolation",
            "These flags give the container broad access to the host.",
            server.origin, snippet=clip(args),
        )
    image = next((a for a in server.args if "/" in a and not a.startswith(("-", "."))), "")
    if image and "@sha256:" not in image:
        extension.finding(
            "supply.unpinned-runner", "opsec", Severity.LOW,
            f"Server '{clip(server.name, 40)}' uses a container tag that can change",
            "Tags can be repointed to a different image.",
            server.origin, snippet=clip(image), fix="Pin the image by digest.",
        )


def _is_plaintext_secret(key: str, value: str) -> bool:
    if not value or ENV_REFERENCE.match(value) or "${" in value:
        return False
    if any(p.search(value) for _, p in SECRET_PATTERNS):
        return True
    bare = value.removeprefix("Bearer ").strip()
    return (is_secret_name(key) or key.lower() == "authorization") and looks_random(bare, 3.0) and len(bare) >= 8


def _hook(extension: Extension, hook: HookDecl) -> None:
    label = f"{hook.event} hook"
    if hook.type == "http":
        _http_hook(extension, hook, label)
    elif hook.type == "command":
        _command_hook(extension, hook, label)
    elif hook.prompt:
        documents.check_text(extension, hook.prompt, hook.origin, 0, label, strict=True)


def _http_hook(extension: Extension, hook: HookDecl, label: str) -> None:
    host = urlsplit(hook.url).hostname or hook.url
    extension.capability(NET, REACH_HOOK, hook.origin, 0, label)
    extension.hosts.add(host.lower())
    if host in LOCALHOST:
        return
    sees_input = hook.event in TOOL_EVENTS | PROMPT_EVENTS
    extension.finding(
        "backdoor.hook-sends-data", "backdoor", Severity.HIGH if sees_input else Severity.MEDIUM,
        f"{label} sends session data to {clip(host, 60)}",
        "HTTP hooks post the event as JSON"
        + (", which includes prompts or tool input and output." if sees_input else "."),
        hook.origin, snippet=clip(hook.url),
    )
    if hook.allowed_env:
        extension.finding(
            "opsec.hook-env-access", "opsec", Severity.MEDIUM,
            f"{label} may send environment variables to {clip(host, 60)}",
            f"Allowed: {clip(', '.join(hook.allowed_env), 100)}.",
            hook.origin,
        )


def _command_hook(extension: Extension, hook: HookDecl, label: str) -> None:
    command = " ".join([hook.command, *hook.args]).strip()
    if not command:
        return
    extension.capability(EXEC, REACH_HOOK, hook.origin, 0, label)
    shell.scan_command(extension, command, hook.origin, 0, REACH_HOOK)
    if hook.event in CONTEXT_EVENTS:
        extension.finding(
            "instructions.hook-context", "opsec", Severity.INFO,
            f"{label} can add text to what Claude reads",
            "Its output becomes context. Read it the same way you would read a skill.",
            hook.origin, snippet=clip(command),
        )
    for path in ROOT_REFERENCE.findall(command):
        if extension.kind in {"plugin", "skill"} and not extension.file(path) and path not in extension.binaries:
            extension.finding(
                "package.hook-missing-script", "backdoor", Severity.MEDIUM,
                f"{label} runs a file that is not in the package",
                f"'{clip(path, 80)}' was not found, so it may be created later.",
                hook.origin, snippet=clip(command),
            )
            continue
        capabilities = extension.file_caps.get(path, set())
        if NET in capabilities:
            sees_data = hook.event in TOOL_EVENTS | PROMPT_EVENTS
            extension.finding(
                "backdoor.hook-network", "backdoor", Severity.MEDIUM,
                f"{label} script uses the network",
                ("It runs with access to prompts or tool data. " if sees_data else "It runs automatically. ")
                + "Check what it sends.",
                path, snippet=clip(command),
            )
    if hook.event in AUTOMATIC_EVENTS and NET in {c.name for c in extension.capabilities if c.file == hook.origin}:
        extension.finding(
            "backdoor.hook-network", "backdoor", Severity.MEDIUM,
            f"{label} uses the network as soon as a session starts",
            "It needs no action from you.", hook.origin, snippet=clip(command),
        )


def _manifest(extension: Extension) -> None:
    data = extension.manifest
    server = data.get("server") if isinstance(data.get("server"), dict) else {}
    entry = str(server.get("entry_point") or "").removeprefix("./")
    if server.get("type") == "binary":
        extension.gap(entry or "server", "the server is a compiled binary, so its behavior was not analyzed")
    elif entry and not extension.file(entry) and entry not in extension.binaries:
        extension.finding(
            "package.missing-entry-point", "backdoor", Severity.MEDIUM,
            "Manifest points at a server file that is not in the package",
            f"'{clip(entry, 80)}' is missing, so the code that runs may not be what was scanned.",
            "manifest.json",
        )
    if data.get("tools_generated") or data.get("prompts_generated"):
        extension.gap("tools", "tools or prompts are generated at run time, so the list here may be incomplete")
    user_config = data.get("user_config")
    if isinstance(user_config, dict):
        for key, field in user_config.items():
            if isinstance(field, dict) and is_secret_name(str(key)) and not field.get("sensitive"):
                extension.finding(
                    "opsec.unmasked-secret", "opsec", Severity.MEDIUM,
                    f"Setting '{clip(str(key), 40)}' looks like a credential but is not marked sensitive",
                    "It will be shown on screen and may be stored without protection.",
                    "manifest.json", fix='Add "sensitive": true.',
                )
    if extension.hosts and not data.get("privacy_policies"):
        extension.finding(
            "opsec.no-privacy-policy", "opsec", Severity.INFO,
            "Extension contacts outside services but lists no privacy policy",
            "The MCPB spec expects one when user data goes to outside services.",
            "manifest.json",
        )


def _plugin(extension: Extension) -> None:
    for module in extension.manifest.get("_hook_modules", []):
        extension.finding(
            "backdoor.in-process-module", "backdoor", Severity.LOW,
            "Plugin loads code directly into Claude's interface",
            "Unlike a hook, this code runs in-process rather than as a separate command.",
            "hooks/hooks.json", snippet=clip(str(module)),
        )
    for file in extension.files:
        if file.path.startswith("bin/"):
            name = file.path.split("/", 1)[1].rsplit(".", 1)[0].lower()
            if name in COMMON_COMMANDS:
                extension.finding(
                    "backdoor.path-shadowing", "backdoor", Severity.HIGH,
                    f"Plugin ships its own '{clip(name, 30)}' command",
                    "Files in bin/ go on PATH for Claude's shell, so this can replace the real one.",
                    file.path,
                )


def _settings(extension: Extension) -> None:
    settings = extension.settings
    origin = extension.location
    permissions = settings.get("permissions")
    if isinstance(permissions, dict):
        if permissions.get("defaultMode") == "bypassPermissions":
            extension.capability(EXEC, REACH_TOOL, origin, 0, "built-in Bash with prompts bypassed")
            extension.finding(
                "opsec.bypass-permissions", "opsec", Severity.HIGH,
                "Permission prompts are bypassed by default",
                "Every tool call runs without review, including ones caused by prompt injection.",
                origin,
            )
        allow = permissions.get("allow")
        for rule in allow if isinstance(allow, list) else []:
            if str(rule) in {"Bash", "Bash(*)", "PowerShell", "PowerShell(*)"}:
                extension.capability(EXEC, REACH_TOOL, origin, 0, f"built-in {rule} is auto-approved")
                extension.finding(
                    "opsec.broad-allowed-tools", "opsec", Severity.HIGH,
                    f"'{rule}' is auto-approved",
                    "Any command runs without a prompt.", origin,
                    fix="Allow specific commands only.",
                )
    if settings.get("enableAllProjectMcpServers") is True:
        extension.finding(
            "opsec.auto-project-servers", "opsec", Severity.MEDIUM,
            "Every MCP server named in a project is approved automatically",
            "Opening a repository could start servers its author chose.",
            origin, fix="Approve project servers one at a time.",
        )
    env = settings.get("env")
    if isinstance(env, dict):
        base = str(env.get("ANTHROPIC_BASE_URL", ""))
        host = urlsplit(base).hostname or ""
        if base and not host.endswith("anthropic.com") and host not in LOCALHOST:
            extension.finding(
                "backdoor.api-redirect", "backdoor", Severity.HIGH,
                f"Claude's API traffic is redirected to {clip(host, 60)}",
                "That host could read your prompts and API key. Make sure you set this yourself.",
                origin,
            )
        for key, value in env.items():
            if _is_plaintext_secret(str(key), str(value)):
                extension.finding(
                    "opsec.plaintext-secret", "opsec", Severity.HIGH,
                    f"Settings store {clip(str(key), 40)} in plain text",
                    "The value is not shown here.", origin,
                )


def _undeclared_tools(extension: Extension) -> None:
    declared = {t.name for t in extension.tools if t.source == "manifest"}
    found = {t.name: t for t in extension.tools if t.source == "code"}
    if not declared or not found or extension.manifest.get("tools_generated"):
        return
    for name, tool in found.items():
        if name not in declared:
            extension.finding(
                "backdoor.undeclared-tool", "backdoor", Severity.MEDIUM,
                f"Tool '{clip(name, 40)}' is in the code but not in the manifest",
                "The install screen shows the manifest, so this tool would not be listed.",
                tool.file, tool.line,
            )
    listed = {t.name: t for t in extension.tools if t.source == "manifest"}
    for name, tool in found.items():
        other = listed.get(name)
        if other and other.description.strip() and tool.description.strip() and other.description.strip() != tool.description.strip():
            extension.finding(
                "backdoor.description-mismatch", "backdoor", Severity.MEDIUM,
                f"Tool '{clip(name, 40)}' has different descriptions in code and manifest",
                "Claude sees the one in the code; a reviewer may only read the manifest.",
                tool.file, tool.line,
            )


def _infer_outside_content(extension: Extension) -> None:
    subjects = [extension.name, *(s.name for s in extension.servers), *(t.name for t in extension.tools)]
    subjects += [urlsplit(s.url).hostname or "" for s in extension.servers if s.url]
    subjects += [_package_argument(s.args) for s in extension.servers]
    for subject in subjects:
        tokens = set(words(subject))
        hits = tokens & OUTSIDE_CONTENT
        if hits or (tokens & FETCH_VERBS and tokens & FETCH_NOUNS):
            reason = sorted(hits)[0] if hits else "web fetching"
            extension.capability(UNTRUSTED, REACH_INFERRED, "", 0, f"'{clip(subject, 40)}' suggests {reason}")


def _coverage(extension: Extension) -> None:
    for path in extension.binaries:
        extension.gap(path, "compiled file; its behavior was not analyzed")
    if extension.vendored_files:
        extension.gap(
            "vendored dependencies",
            f"{extension.vendored_files} files of third-party code were skipped; only their install scripts were checked",
        )
    if extension.kind == "mcpb":
        extension.gap("signature", "package signatures are not verified")
    code = {".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx", ".jsx", ".sh", ".ps1"}
    other = sorted({f.suffix for f in extension.files if f.suffix in {".rb", ".go", ".rs", ".java", ".php", ".cs", ".lua", ".pl"}})
    if other:
        extension.gap(", ".join(other) + " files", "these languages are only checked for text patterns")
    if extension.kind in {"plugin", "mcpb", "source"} and not any(f.suffix in code for f in extension.files):
        if extension.servers and not all(s.url or s.command in RUNNERS for s in extension.servers):
            extension.gap("server code", "the package declares a server but ships no code that could be read")
