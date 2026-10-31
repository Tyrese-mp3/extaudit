"""Build throwaway extensions in temp folders. Test inputs are strings, never run."""

from __future__ import annotations

import io
import json
import tempfile
import zipfile
from pathlib import Path

from extaudit import analyzers, loaders
from extaudit.model import Extension, PackageFile, Severity


def write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
    return root


def scan(files: dict[str, str | bytes]) -> Extension:
    """Write files to a temp folder, then load and analyze them as one extension."""
    with tempfile.TemporaryDirectory() as folder:
        root = write_tree(Path(folder) / "sample", files)
        extension = loaders.load_directory(root)
        return analyzers.analyze(extension)


def scan_in_memory(files: dict[str, str]) -> Extension:
    """Analyze without touching disk, for text that antivirus blocks if written to a file."""
    extension = Extension(name="memory", kind="source", location="memory")
    extension.files = [PackageFile(path, text.encode()) for path, text in files.items()]
    return analyzers.analyze(extension)


def scan_python(source: str) -> Extension:
    return scan({"server.py": source})


def scan_js(source: str, name: str = "server.ts") -> Extension:
    return scan({name: source})


def plugin(files: dict[str, str | bytes], name: str = "demo") -> dict[str, str | bytes]:
    return {".claude-plugin/plugin.json": json.dumps({"name": name, "version": "1.0.0"}), **files}


def zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return buffer.getvalue()


def rules(extension: Extension) -> set[str]:
    return {f.rule for f in extension.findings}


def worst(extension: Extension, rule: str) -> Severity | None:
    levels = [f.severity for f in extension.findings if f.rule == rule]
    return max(levels) if levels else None


def capability_pairs(extension: Extension) -> set[tuple[str, str]]:
    return {(c.name, c.reach) for c in extension.capabilities}
