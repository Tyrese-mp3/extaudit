"""Find what is installed on this machine.

Only the settings needed for the scan are read. Credential files are never opened,
and in ~/.claude.json only the MCP server entries are looked at.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import declarations, loaders
from .model import Extension, PackageFile


def desktop_config_dir(home: Path) -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", home / "AppData" / "Roaming")) / "Claude"
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Claude"
    return Path(os.environ.get("XDG_CONFIG_HOME", home / ".config")) / "Claude"


def discover(
    home: Path | None = None,
    desktop_dir: Path | None = None,
    projects: list[Path] | None = None,
) -> tuple[list[Extension], list[str]]:
    """Return installed extensions and a list of the places that were checked."""
    home = home or Path.home()
    desktop_dir = desktop_dir or desktop_config_dir(home)
    projects = projects if projects is not None else [Path.cwd()]
    found: list[Extension] = []
    searched: list[str] = []
    errors: list[str] = []

    def add_config(path: Path, label: str) -> None:
        searched.append(str(path))
        if path.is_file():
            _collect(lambda: loaders.load_config(path, label), found, errors)

    add_config(desktop_dir / "claude_desktop_config.json", "claude_desktop_config.json")
    extensions_dir = desktop_dir / "Claude Extensions"
    searched.append(str(extensions_dir))
    for folder in _subfolders(extensions_dir):
        _collect(lambda: [loaders.load_directory(folder)], found, errors)

    claude = home / ".claude"
    add_config(claude / "settings.json", "settings.json")
    add_config(claude / "settings.local.json", "settings.local.json")
    _claude_json(home / ".claude.json", found, searched)
    _plugins(claude / "plugins", found, searched, errors)
    _skills(claude / "skills", found, searched, errors)
    _loose_markdown(claude, found, searched)

    for project in projects:
        add_config(project / ".mcp.json", f"{project.name}/.mcp.json")
        add_config(project / ".claude" / "settings.json", f"{project.name}/.claude/settings.json")
        add_config(project / ".claude" / "settings.local.json", f"{project.name}/.claude/settings.local.json")
        _skills(project / ".claude" / "skills", found, searched, errors)

    unique: dict[tuple, Extension] = {}
    for extension in found:
        unique.setdefault((extension.kind, extension.name, extension.location), extension)
    return list(unique.values()), [*searched, *(f"could not read: {e}" for e in errors)]


def _collect(load, found: list[Extension], errors: list[str]) -> None:
    try:
        found.extend(load())
    except loaders.LoadError as exc:
        errors.append(str(exc))


def _subfolders(path: Path) -> list[Path]:
    if not path.is_dir():
        return []
    return [p for p in sorted(path.iterdir()) if p.is_dir() and not p.is_symlink()]


def _claude_json(path: Path, found: list[Extension], searched: list[str]) -> None:
    searched.append(str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    sections = [("~/.claude.json", data.get("mcpServers"))]
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, settings in projects.items():
            if isinstance(settings, dict):
                sections.append((f"~/.claude.json ({project})", settings.get("mcpServers")))
    for label, servers in sections:
        if isinstance(servers, dict) and servers:
            found.extend(declarations.from_config({"mcpServers": servers}, label, str(path)))


def _plugins(folder: Path, found: list[Extension], searched: list[str], errors: list[str]) -> None:
    manifest = folder / "installed_plugins.json"
    searched.append(str(manifest))
    paths: list[Path] = []
    try:
        data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        plugins = data.get("plugins", {}) if isinstance(data, dict) else {}
        for installs in plugins.values() if isinstance(plugins, dict) else []:
            for install in installs if isinstance(installs, list) else [installs]:
                location = install.get("installPath") if isinstance(install, dict) else None
                if location:
                    paths.append(Path(location))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        pass
    cache = folder / "cache"
    if not paths and cache.is_dir():
        searched.append(str(cache))
        for marketplace in _subfolders(cache):
            for plugin in _subfolders(marketplace):
                versions = _subfolders(plugin)
                paths.extend(versions[-1:] if versions else [])
    for path in paths:
        if path.is_dir():
            _collect(lambda: [loaders.load_directory(path)], found, errors)


def _skills(folder: Path, found: list[Extension], searched: list[str], errors: list[str]) -> None:
    searched.append(str(folder))
    for skill in _subfolders(folder):
        if (skill / "SKILL.md").is_file():
            _collect(lambda: [loaders.load_directory(skill)], found, errors)


def _loose_markdown(claude: Path, found: list[Extension], searched: list[str]) -> None:
    """Personal commands and agents have no package of their own, so group them."""
    extension = Extension(name="personal commands and agents", kind="plugin", location=str(claude))
    for name in ("commands", "agents"):
        folder = claude / name
        searched.append(str(folder))
        if folder.is_dir():
            for path in sorted(folder.glob("*.md")):
                try:
                    extension.files.append(PackageFile(f"{name}/{path.name}", path.read_bytes()))
                except OSError:
                    continue
    if extension.files:
        declarations.parse(extension)
        found.append(extension)
