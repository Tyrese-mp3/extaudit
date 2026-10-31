"""Parse what an extension declares: manifests, hooks, MCP servers and skills."""

from __future__ import annotations

import json
import re

from .model import Doc, Extension, HookDecl, PackageFile, ServerDecl, ToolDecl

EXTENSION_MARKDOWN = re.compile(r"(?:^|/)(commands|agents)/[^/]+\.md$", re.I)


def is_mcpb_manifest(file: PackageFile | None) -> bool:
    data = _json(file) if file else None
    return isinstance(data, dict) and "server" in data


def parse(extension: Extension) -> None:
    manifest = extension.file("manifest.json")
    if extension.kind == "mcpb" and manifest:
        _parse_manifest(extension, manifest)
    plugin = extension.file(".claude-plugin/plugin.json")
    if plugin:
        _parse_plugin(extension, plugin)
    for path in (".mcp.json",):
        file = extension.file(path)
        if file:
            add_mcp_json(extension, _json_or_gap(extension, file), path)
    hooks = extension.file("hooks/hooks.json")
    if hooks:
        _parse_hooks_file(extension, hooks)
    if extension.kind in {"plugin", "skill"}:
        _parse_docs(extension)
    lsp = extension.file(".lsp.json")
    if lsp:
        _parse_command_map(extension, lsp, "lsp")
    monitors = extension.file("monitors/monitors.json")
    if monitors:
        _parse_command_map(extension, monitors, "monitor")


def from_config(data: dict, label: str, location: str) -> list[Extension]:
    """Build extensions from a config file: one per MCP server, one for settings."""
    extensions: list[Extension] = []
    servers = data.get("mcpServers")
    if not isinstance(servers, dict):
        servers = {k: v for k, v in data.items() if _is_server_entry(v)}
    for name, entry in servers.items():
        extension = Extension(name=str(name), kind="mcp-config", location=location)
        add_server(extension, str(name), entry, label)
        extensions.append(extension)
    if {"hooks", "permissions", "env"} & data.keys() or "enableAllProjectMcpServers" in data:
        extension = Extension(name=f"settings ({label})", kind="settings", location=location)
        extension.settings = {
            k: data[k]
            for k in ("permissions", "enableAllProjectMcpServers", "env", "apiKeyHelper")
            if k in data
        }
        if isinstance(data.get("hooks"), dict):
            add_hooks(extension, data["hooks"], label)
        extensions.append(extension)
    return extensions


def add_mcp_json(extension: Extension, data: object, origin: str) -> None:
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") if isinstance(data.get("mcpServers"), dict) else data
    for name, entry in servers.items():
        add_server(extension, str(name), entry, origin)


def add_server(extension: Extension, name: str, entry: object, origin: str) -> None:
    if not isinstance(entry, dict):
        return
    extension.servers.append(
        ServerDecl(
            name=name,
            command=str(entry.get("command", "")),
            args=_strings(entry.get("args")),
            env=_string_map(entry.get("env")),
            url=str(entry.get("url", "")),
            transport=str(entry.get("type") or entry.get("transport") or ""),
            headers=_string_map(entry.get("headers")),
            origin=origin,
        )
    )


def add_hooks(extension: Extension, mapping: dict, origin: str) -> None:
    for event, groups in mapping.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for hook in group.get("hooks") or []:
                if isinstance(hook, dict):
                    extension.hooks.append(_hook(str(event), str(group.get("matcher", "")), hook, origin))


def parse_frontmatter(text: str) -> tuple[dict, str, int]:
    """Read simple YAML frontmatter: scalars, lists and raw nested blocks."""
    if not text.startswith("---"):
        return {}, text, 1
    end = text.find("\n---", 3)
    if end < 0:
        return {}, text, 1
    block = text[3:end].strip("\r\n")
    body = text[end + 4:].split("\n", 1)
    data: dict = {}
    key = ""
    for raw in block.splitlines():
        if raw.lstrip().startswith("#"):
            data.setdefault("_comments", []).append(raw.strip())
            continue
        match = re.match(r"([A-Za-z_][\w-]*):\s*(.*)$", raw)
        if match:
            key = match.group(1)
            value = match.group(2).strip()
            data[key] = value.strip("\"'") if value else []
        elif key and raw.strip().startswith("- ") and isinstance(data.get(key), list):
            data[key].append(raw.strip()[2:].strip().strip("\"'"))
        elif key and raw.strip():
            existing = data.get(key)
            if isinstance(existing, list):
                data[key] = "\n".join([*existing, raw])
            else:
                data[key] = f"{existing}\n{raw}"
    return data, body[1] if len(body) > 1 else "", block.count("\n") + 4


def _parse_manifest(extension: Extension, file: PackageFile) -> None:
    data = _json_or_gap(extension, file)
    if not isinstance(data, dict):
        return
    extension.manifest = data
    extension.name = str(data.get("name") or extension.name)
    extension.version = str(data.get("version") or "")
    server = data.get("server")
    if isinstance(server, dict):
        config = server.get("mcp_config")
        if isinstance(config, dict):
            add_server(extension, extension.name, config, file.path)
    for tool in _dict_items(data.get("tools")):
        extension.tools.append(
            ToolDecl(str(tool.get("name", "")), str(tool.get("description", "")), "manifest", file.path)
        )
    for prompt in _dict_items(data.get("prompts")):
        extension.docs.append(Doc(file.path, "prompt", str(prompt.get("text", ""))))


def _parse_plugin(extension: Extension, file: PackageFile) -> None:
    data = _json_or_gap(extension, file)
    if not isinstance(data, dict):
        return
    extension.manifest = data
    extension.name = str(data.get("name") or extension.name)
    extension.version = str(data.get("version") or "")
    for path in _paths(data.get("mcpServers")):
        target = extension.file(path)
        if target:
            add_mcp_json(extension, _json_or_gap(extension, target), path)
    if isinstance(data.get("mcpServers"), dict):
        add_mcp_json(extension, data["mcpServers"], file.path)
    for path in _paths(data.get("hooks")):
        target = extension.file(path)
        if target and path != "hooks/hooks.json":
            _parse_hooks_file(extension, target)
    if isinstance(data.get("hooks"), dict):
        add_hooks(extension, data["hooks"].get("hooks", data["hooks"]), file.path)


def _parse_hooks_file(extension: Extension, file: PackageFile) -> None:
    data = _json_or_gap(extension, file)
    if not isinstance(data, dict):
        return
    add_hooks(extension, data.get("hooks") if isinstance(data.get("hooks"), dict) else {}, file.path)
    modules = data.get("modules")
    if isinstance(modules, list):
        extension.manifest.setdefault("_hook_modules", []).extend(str(m) for m in modules)


def _parse_docs(extension: Extension) -> None:
    for file in extension.files:
        name = file.path.rsplit("/", 1)[-1]
        if name == "SKILL.md":
            kind = "skill"
        else:
            match = EXTENSION_MARKDOWN.search(file.path)
            if not match:
                continue
            kind = match.group(1).lower().rstrip("s")
        frontmatter, body, body_line = parse_frontmatter(file.text)
        extension.docs.append(Doc(file.path, kind, body, frontmatter, body_line))
        if file.path == "SKILL.md":
            extension.name = str(frontmatter.get("name") or extension.name)


def _parse_command_map(extension: Extension, file: PackageFile, label: str) -> None:
    data = _json_or_gap(extension, file)
    entries = data.values() if isinstance(data, dict) else data if isinstance(data, list) else []
    for index, entry in enumerate(entries):
        if isinstance(entry, dict) and entry.get("command"):
            add_server(extension, f"{label}-{index + 1}", entry, file.path)


def _hook(event: str, matcher: str, hook: dict, origin: str) -> HookDecl:
    return HookDecl(
        event=event,
        matcher=matcher,
        type=str(hook.get("type", "command")),
        command=str(hook.get("command", "")),
        args=_strings(hook.get("args")),
        url=str(hook.get("url", "")),
        headers=_string_map(hook.get("headers")),
        prompt=str(hook.get("prompt", "")),
        condition=str(hook.get("if", "")),
        allowed_env=_strings(hook.get("allowedEnvVars")),
        origin=origin,
    )


def _is_server_entry(value: object) -> bool:
    return isinstance(value, dict) and ("command" in value or "url" in value)


def _json(file: PackageFile) -> object:
    try:
        return json.loads(file.text)
    except (ValueError, RecursionError):
        return None


def _json_or_gap(extension: Extension, file: PackageFile) -> object:
    data = _json(file)
    if data is None:
        extension.gap(file.path, "JSON could not be parsed, so its settings were not checked")
    return data


def _paths(value: object) -> list[str]:
    items = value if isinstance(value, list) else [value]
    return [item.removeprefix("./") for item in items if isinstance(item, str)]


def _strings(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _string_map(value: object) -> dict[str, str]:
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def _dict_items(value: object) -> list[dict]:
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []
