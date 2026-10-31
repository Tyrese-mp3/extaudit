"""Read extensions from disk without unpacking or running anything.

Archives are read into memory entry by entry, so a hostile zip cannot write
outside the scan. Size limits guard against zip bombs, and symlinks are never
followed.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from . import declarations
from .model import Extension, PackageFile, Severity

MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_FILES = 20_000
MAX_ZIP_RATIO = 200
VIRUS_ERRORS = {225, 226}  # Windows: file contains a virus / potentially unwanted software

ARCHIVE_SUFFIXES = {".mcpb", ".dxt", ".zip"}
SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
VENDOR_DIRS = {"node_modules", "site-packages"}
BINARY_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".node", ".wasm", ".pyc", ".pyd", ".bin", ".jar", ".class"}
ASSET_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".bmp", ".pdf",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".webm", ".map",
}


class LoadError(Exception):
    """The path cannot be read as an extension."""


def load_path(path: str | Path) -> list[Extension]:
    """Load every extension found at a path."""
    target = Path(path)
    if not target.exists():
        raise LoadError(f"{target} does not exist")
    if target.is_file():
        if target.suffix.lower() in ARCHIVE_SUFFIXES:
            return [load_archive(target)]
        if target.suffix.lower() == ".json":
            return load_config(target)
        if target.name == "SKILL.md":
            return [load_directory(target.parent)]
        raise LoadError(f"{target} is not a .mcpb, .dxt, .zip, .json or SKILL.md file")

    if _is_project(target):
        return [load_directory(target)]
    roots = _extension_roots(target, depth=4)
    if roots:
        return [load_directory(root) for root in roots]
    extension = load_directory(target)
    if not extension.files:
        raise LoadError(f"{target} has nothing to scan")
    return [extension]


def load_archive(path: Path) -> Extension:
    extension = Extension(name=path.stem, kind="mcpb", location=str(path))
    try:
        with zipfile.ZipFile(path) as archive:
            read_archive(archive, extension)
    except zipfile.BadZipFile as exc:
        raise LoadError(f"{path} is not a readable zip archive") from exc
    _finish(extension)
    return extension


def load_directory(root: Path) -> Extension:
    extension = Extension(name=root.name, kind="source", location=str(root))
    _read_tree(root, extension)
    _finish(extension)
    return extension


def load_config(path: Path, label: str | None = None) -> list[Extension]:
    """Load a settings or MCP config file. Only the keys that matter are kept."""
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError) as exc:
        raise LoadError(f"{path} is not readable JSON") from exc
    if not isinstance(data, dict):
        raise LoadError(f"{path} is not a JSON object")
    return declarations.from_config(data, path.name if label is None else label, str(path))


def _finish(extension: Extension) -> None:
    extension.kind = _detect_kind(extension)
    parse_declarations(extension)


def parse_declarations(extension: Extension) -> None:
    try:
        declarations.parse(extension)
    except Exception as exc:
        extension.gap("package metadata", f"could not be fully read ({type(exc).__name__})")


def add_entry(extension: Extension, relative: str, data: bytes) -> None:
    """Add one file from a downloaded package, with the same filters as a folder scan."""
    pure = PurePosixPath(relative)
    parts = set(pure.parts)
    if parts & SKIP_DIRS:
        return
    if parts & VENDOR_DIRS:
        extension.vendored_files += 1
        if pure.name == "package.json":
            try:
                manifest = json.loads(data.decode("utf-8-sig"))
            except (ValueError, RecursionError):
                return
            if isinstance(manifest, dict) and isinstance(manifest.get("name"), str):
                extension.vendored[str(manifest["name"])] = manifest
        return
    if pure.suffix.lower() in ASSET_SUFFIXES:
        extension.assets_skipped += 1
        return
    _add_file(extension, relative, data)


def _detect_kind(extension: Extension) -> str:
    paths = {f.path for f in extension.files}
    if "manifest.json" in paths and declarations.is_mcpb_manifest(extension.file("manifest.json")):
        return "mcpb"
    if ".claude-plugin/plugin.json" in paths or "hooks/hooks.json" in paths or ".mcp.json" in paths:
        return "plugin"
    if "SKILL.md" in paths:
        return "skill"
    return "source"


def _is_project(path: Path) -> bool:
    """True when the folder itself is one extension rather than a collection."""
    if (path / ".claude-plugin" / "marketplace.json").exists() and not (
        path / ".claude-plugin" / "plugin.json"
    ).exists():
        return False
    markers = ("package.json", "pyproject.toml", "requirements.txt", "setup.py")
    return _is_extension_root(path) or any((path / m).exists() for m in markers)


def _is_extension_root(path: Path) -> bool:
    if (path / ".claude-plugin" / "plugin.json").exists() or (path / "SKILL.md").exists():
        return True
    if (path / "hooks" / "hooks.json").exists() or (path / ".mcp.json").exists():
        return True
    manifest = path / "manifest.json"
    if manifest.exists():
        try:
            data = json.loads(manifest.read_text(encoding="utf-8-sig"))
        except (OSError, ValueError, RecursionError):
            return False
        return isinstance(data, dict) and "server" in data
    return False


def _extension_roots(root: Path, depth: int) -> list[Path]:
    found: list[Path] = []

    def walk(folder: Path, remaining: int) -> None:
        if _is_extension_root(folder):
            found.append(folder)
            return
        if remaining == 0:
            return
        try:
            children = sorted(folder.iterdir())
        except OSError:
            return
        for child in children:
            if not child.is_dir() or _is_link(child):
                continue
            if child.name in SKIP_DIRS or child.name in VENDOR_DIRS or child.name.startswith("."):
                continue
            walk(child, remaining - 1)

    walk(root, depth)
    return found


def _is_link(path: Path) -> bool:
    return path.is_symlink() or path.is_junction()


def _read_tree(root: Path, extension: Extension) -> None:
    total = 0
    count = 0
    for current, dirs, names in os.walk(root, followlinks=False):
        base = Path(current)
        for name in list(dirs):
            full = base / name
            if _is_link(full):
                dirs.remove(name)
                _note_link(extension, root, full)
            elif name in SKIP_DIRS:
                dirs.remove(name)
            elif name in VENDOR_DIRS:
                dirs.remove(name)
                _read_vendor_tree(full, root, extension)
        for name in names:
            full = base / name
            relative = full.relative_to(root).as_posix()
            if full.is_symlink():
                _note_link(extension, root, full)
                continue
            count += 1
            if count > MAX_FILES:
                extension.gap(relative, f"stopped after {MAX_FILES} files")
                return
            try:
                size = full.stat().st_size
                if size > MAX_FILE_BYTES and full.suffix.lower() not in ASSET_SUFFIXES:
                    extension.gap(relative, f"file is {size // 1024} KB, over the size limit")
                    continue
                if full.suffix.lower() in ASSET_SUFFIXES:
                    extension.assets_skipped += 1
                    continue
                total += size
                if total > MAX_PACKAGE_BYTES:
                    extension.gap(str(root), "package is over the size limit; remaining files skipped")
                    return
                _add_file(extension, relative, full.read_bytes())
            except OSError as exc:
                _note_unreadable(extension, relative, exc)


def _note_unreadable(extension: Extension, relative: str, exc: OSError) -> None:
    if exc.errno == errno.EINVAL or getattr(exc, "winerror", None) in VIRUS_ERRORS:
        extension.finding(
            "package.read-blocked", "backdoor", Severity.HIGH,
            "The operating system refused to read this file",
            "On Windows this usually means antivirus flagged the file. Check your security "
            "app's protection history before trusting this extension.",
            file=relative,
        )
        extension.gap(relative, "file was blocked, probably by antivirus, so it was not analyzed")
    else:
        extension.gap(relative, f"could not read file ({exc.strerror or 'I/O error'})")


def _read_vendor_tree(folder: Path, root: Path, extension: Extension) -> None:
    """Keep only vendored package manifests; third-party code is not analyzed."""
    for current, dirs, names in os.walk(folder, followlinks=False):
        extension.vendored_files += len(names)
        dirs[:] = [d for d in dirs if not _is_link(Path(current) / d)]
        if "package.json" in names:
            _add_vendor_manifest(extension, Path(current) / "package.json", root)


def _add_vendor_manifest(extension: Extension, path: Path, root: Path) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        _note_unreadable(extension, path.relative_to(root).as_posix(), exc)
        return
    except (ValueError, RecursionError):
        return
    if isinstance(data, dict) and isinstance(data.get("name"), str):
        extension.vendored[str(data["name"])] = data


def read_archive(archive: zipfile.ZipFile, extension: Extension) -> None:
    total = 0
    seen: set[str] = set()
    for info in archive.infolist()[: MAX_FILES + 1]:
        name = info.filename
        if info.is_dir():
            continue
        if name in seen:
            extension.finding(
                "package.duplicate-entry", "backdoor", Severity.MEDIUM,
                "Archive holds two files with the same name",
                "Different tools may read different copies, so a review can see one file while "
                "Claude Desktop installs the other.",
                file=name,
            )
            continue
        seen.add(name)
        pure = PurePosixPath(name.replace("\\", "/"))
        if pure.is_absolute() or ".." in pure.parts or ":" in pure.parts[0]:
            extension.finding(
                "package.path-traversal", "backdoor", Severity.HIGH,
                "Archive entry points outside the package",
                "An unsafe unpacker would write this file somewhere else on disk.",
                file=name,
            )
            continue
        if stat.S_ISLNK(info.external_attr >> 16):
            extension.finding(
                "package.symlink", "backdoor", Severity.HIGH,
                "Archive contains a symbolic link",
                "A link can redirect reads or writes to files outside the package.",
                file=name,
            )
            continue
        relative = pure.as_posix()
        parts = set(pure.parts)
        if parts & SKIP_DIRS:
            continue
        if parts & VENDOR_DIRS:
            extension.vendored_files += 1
            if pure.name == "package.json" and info.file_size < MAX_FILE_BYTES:
                _add_vendor_bytes(archive, info, extension)
            continue
        suffix = pure.suffix.lower()
        if suffix in ASSET_SUFFIXES:
            extension.assets_skipped += 1
            continue
        if info.file_size > MAX_FILE_BYTES:
            extension.gap(relative, f"file is {info.file_size // 1024} KB, over the size limit")
            continue
        if info.compress_size and info.file_size / info.compress_size > MAX_ZIP_RATIO:
            extension.gap(relative, "compression ratio looks like a zip bomb; entry skipped")
            continue
        total += info.file_size
        if total > MAX_PACKAGE_BYTES:
            extension.gap(extension.location, "package is over the size limit; remaining files skipped")
            return
        try:
            _add_file(extension, relative, archive.read(info))
        except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error):
            extension.gap(relative, "archive entry could not be read (corrupt or encrypted)")


def _add_vendor_bytes(archive: zipfile.ZipFile, info: zipfile.ZipInfo, extension: Extension) -> None:
    try:
        data = json.loads(archive.read(info).decode("utf-8-sig"))
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error, ValueError, RecursionError):
        return
    if isinstance(data, dict) and isinstance(data.get("name"), str):
        extension.vendored[str(data["name"])] = data


def _add_file(extension: Extension, relative: str, data: bytes) -> None:
    suffix = PurePosixPath(relative).suffix.lower()
    if suffix in BINARY_SUFFIXES or b"\x00" in data[:8192]:
        extension.binaries.append(relative)
        extension.binary_data[relative] = data
        return
    extension.files.append(PackageFile(relative, data))


def _note_link(extension: Extension, root: Path, link: Path) -> None:
    try:
        target = Path(os.path.realpath(link))
        inside = target.is_relative_to(Path(os.path.realpath(root)))
    except OSError:
        inside = False
    if not inside:
        extension.finding(
            "package.symlink-escape", "backdoor", Severity.HIGH,
            "Symbolic link points outside the package",
            "The link was not followed, so whatever it points at was not scanned.",
            file=link.relative_to(root).as_posix(),
        )
