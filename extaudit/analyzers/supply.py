"""Dependency and install-time checks."""

from __future__ import annotations

import json
import re
import tomllib

from ..model import REACH_CODE, Extension, Severity
from ..patterns import clip
from . import shell

LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
LOCK_FILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "npm-shrinkwrap.json")
LOOSE_VERSION = re.compile(r"^(?:\*|latest|x|)$", re.I)
REMOTE_VERSION = re.compile(r"^(?:https?:|git\+|git:|github:|[\w.-]+/[\w.-]+$)", re.I)
INDEX_URL = re.compile(r"(?i)^\s*(?:--?index-url|--extra-index-url|-i)\b\s*=?\s*(\S+)")
REGISTRY = re.compile(r"(?i)^\s*(?:@[\w-]+:)?registry\s*=\s*(\S+)")
TRUSTED_REGISTRIES = ("https://registry.npmjs.org", "https://pypi.org")
REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(.*)$")
POPULAR = {
    "requests", "urllib3", "httpx", "numpy", "pandas", "flask", "django", "fastapi", "pydantic",
    "express", "lodash", "axios", "react", "chalk", "commander", "dotenv", "typescript", "zod",
    "anthropic", "openai", "fastmcp", "mcp",
}


def analyze(extension: Extension) -> None:
    for file in extension.files:
        name = file.path.rsplit("/", 1)[-1]
        if name == "package.json":
            _package_json(extension, file.path, file.text)
        elif name.startswith("requirements") and name.endswith(".txt"):
            _requirements(extension, file.path, file.text)
        elif name == "pyproject.toml":
            _pyproject(extension, file.path, file.text)
        elif name in {".npmrc", "pip.conf", "bunfig.toml"}:
            _registry(extension, file.path, file.text)
    for package, data in extension.vendored.items():
        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for key in LIFECYCLE[:3]:
                if key in scripts:
                    _lifecycle(extension, f"node_modules/{package}/package.json", key, str(scripts[key]), vendored=True)


def _package_json(extension: Extension, path: str, text: str) -> None:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        extension.gap(path, "JSON could not be parsed, so dependencies were not checked")
        return
    if not isinstance(data, dict):
        return
    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for key in LIFECYCLE:
            if key in scripts:
                _lifecycle(extension, path, key, str(scripts[key]), vendored=False)
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, dict):
        return
    folder = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
    published = extension.kind in {"npm", "pypi"}  # published packages never include a lockfile
    if dependencies and not published and not any(extension.file(folder + lock) for lock in LOCK_FILES) and not extension.vendored:
        extension.finding(
            "supply.no-lockfile", "opsec", Severity.LOW,
            "Dependencies have no lockfile",
            "Each install can pull different code than the author tested.", path,
            fix="Commit a lockfile.",
        )
    for name, version in dependencies.items():
        extension.dependencies[str(name)] = str(version)
        _version(extension, path, str(name), str(version))
        lookalike(extension, path, str(name))


def _version(extension: Extension, path: str, name: str, version: str) -> None:
    label = clip(name, 50)
    if LOOSE_VERSION.match(version):
        extension.finding(
            "supply.unpinned-dependency", "opsec", Severity.MEDIUM,
            f"Dependency {label} accepts any version",
            "A hijacked release would be picked up automatically.", path,
            fix="Pin a version.",
        )
    elif REMOTE_VERSION.match(version):
        extension.finding(
            "supply.remote-dependency", "opsec", Severity.MEDIUM,
            f"Dependency {label} comes from a URL or repository, not a registry",
            "It skips registry checks and its contents can change.", path,
            snippet=clip(version), fix="Use a published version or pin a commit hash.",
        )


def lookalike(extension: Extension, path: str, name: str) -> None:
    lowered = name.lower()
    for popular in POPULAR:
        if lowered != popular and len(popular) >= 5 and _one_edit(lowered, popular):
            extension.finding(
                "supply.lookalike-package", "backdoor", Severity.HIGH,
                f"Dependency {clip(name, 50)} is one character away from {popular}",
                "Typo-squatted packages are a common way to deliver malware.", path,
            )


def _one_edit(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        differences = [i for i in range(len(a)) if a[i] != b[i]]
        if len(differences) == 1:
            return True
        return (
            len(differences) == 2
            and differences[1] == differences[0] + 1
            and a[differences[0]] == b[differences[1]]
            and a[differences[1]] == b[differences[0]]
        )
    short, long = sorted((a, b), key=len)
    for i in range(len(long)):
        if long[:i] + long[i + 1 :] == short:
            return True
    return False


def _lifecycle(extension: Extension, path: str, key: str, command: str, vendored: bool) -> None:
    extension.install_scripts[f"{path}:{key}"] = command
    if key == "prepare" and not vendored:
        return
    extension.finding(
        "supply.install-script", "backdoor", Severity.MEDIUM if not vendored else Severity.LOW,
        f"Package runs a '{key}' script when installed",
        "This runs automatically, before any review of what the extension does.",
        path, snippet=clip(command),
    )
    shell.scan_command(extension, command, path, 0, REACH_CODE)


def _requirements(extension: Extension, path: str, text: str) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        index = INDEX_URL.match(stripped)
        if index:
            _custom_registry(extension, path, number, index.group(1))
            continue
        if stripped.startswith("-"):
            continue
        if re.search(r"^(?:git\+|https?:)|\s@\s*(?:git\+|https?:)", stripped):
            extension.finding(
                "supply.remote-dependency", "opsec", Severity.MEDIUM,
                "Dependency comes from a URL or repository, not a registry",
                "It skips registry checks and its contents can change.",
                path, number, clip(stripped),
            )
            continue
        match = REQUIREMENT.match(stripped)
        if match:
            name, spec = match.group(1), match.group(2)
            extension.dependencies[name] = spec.strip()
            lookalike(extension, path, name)
            if "==" not in spec:
                extension.finding(
                    "supply.unpinned-dependency", "opsec", Severity.LOW,
                    f"Dependency {clip(name, 50)} is not pinned",
                    "A hijacked release would be picked up automatically.",
                    path, number, clip(stripped), "Pin with ==.",
                )


def _pyproject(extension: Extension, path: str, text: str) -> None:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        extension.gap(path, "TOML could not be parsed, so dependencies were not checked")
        return
    project = data.get("project")
    dependencies = project.get("dependencies") if isinstance(project, dict) else None
    for entry in dependencies if isinstance(dependencies, list) else []:
        match = REQUIREMENT.match(str(entry))
        if match:
            extension.dependencies[match.group(1)] = match.group(2).strip()
            lookalike(extension, path, match.group(1))


def _registry(extension: Extension, path: str, text: str) -> None:
    for number, line in enumerate(text.splitlines(), 1):
        match = REGISTRY.match(line) or INDEX_URL.match(line)
        if match:
            _custom_registry(extension, path, number, match.group(1))


def _custom_registry(extension: Extension, path: str, number: int, url: str) -> None:
    if url.startswith(TRUSTED_REGISTRIES):
        return
    extension.finding(
        "supply.custom-registry", "backdoor", Severity.HIGH,
        "Dependencies are pulled from a custom package source",
        "A different registry can serve different code under familiar package names.",
        path, number, clip(url),
    )
