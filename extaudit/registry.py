"""Read published npm and PyPI packages into memory. Only ever used on request.

Packages come from the official registries over HTTPS, are checked against the
registry's hash, and are unpacked in memory. Nothing is written to disk, installed or
run. The registries learn which package names were requested, and nothing else: no
config values, paths or arguments are ever sent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import io
import json
import tarfile
import urllib.error
import urllib.request
import zipfile
import zlib
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from . import __version__, analyzers, loaders, packages
from .analyzers import supply
from .model import Extension, Severity
from .packages import NPM, PYPI, URL_SAFE_VERSION, PackageSpec

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org"
NPM_DOWNLOAD_HOSTS = {"registry.npmjs.org"}
PYPI_DOWNLOAD_HOSTS = {"files.pythonhosted.org"}
ALLOWED_HOSTS = {"registry.npmjs.org", "pypi.org", "files.pythonhosted.org"}
ABBREVIATED = {"Accept": "application/vnd.npm.install-v1+json"}

TIMEOUT_SECONDS = 30
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_PACKUMENT = 48 * 1024 * 1024
MAX_DOWNLOAD = 128 * 1024 * 1024
MAX_PACKAGES = 40
FRESH_RELEASE_DAYS = 7
NEW_PACKAGE_DAYS = 30
LIFECYCLE = ("preinstall", "install", "postinstall")


class RegistryError(Exception):
    """A package could not be read. Becomes a 'could not check' entry, never a crash."""


class NotFound(RegistryError):
    pass


class Fetcher:
    """HTTPS GET with a fixed list of hosts, a size limit and a timeout."""

    def __init__(self, hosts: set[str] | None = None, allow_http: bool = False, timeout: int = TIMEOUT_SECONDS):
        self.hosts = hosts or ALLOWED_HOSTS
        self.allow_http = allow_http
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_CheckedRedirects(self))

    def check(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https" and not (self.allow_http and parts.scheme == "http"):
            raise RegistryError(f"refused to use {parts.scheme or 'no'} scheme")
        if parts.hostname not in self.hosts:
            raise RegistryError(f"refused to contact {parts.hostname}")

    def get(self, url: str, limit: int, headers: dict[str, str] | None = None) -> bytes:
        self.check(url)
        request = urllib.request.Request(url, headers={"User-Agent": f"extaudit/{__version__}", **(headers or {})})
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                data = response.read(limit + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise NotFound("not found on the registry") from exc
            raise RegistryError(f"the registry answered {exc.code}") from exc
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            raise RegistryError(f"could not reach the registry ({type(exc).__name__})") from exc
        if len(data) > limit:
            raise RegistryError(f"response is over the {limit // (1024 * 1024)} MB limit")
        return data


class _CheckedRedirects(urllib.request.HTTPRedirectHandler):
    """A redirect goes through the same host check as the first request."""

    def __init__(self, fetcher: Fetcher):
        self.fetcher = fetcher

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.fetcher.check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Client:
    def __init__(self, fetcher=None, now: datetime | None = None, depth: int = 0, max_packages: int = MAX_PACKAGES):
        self.fetcher = fetcher or Fetcher()
        self.now = now or datetime.now(timezone.utc)
        self.depth = depth
        self.max_packages = max_packages
        self.results: dict[str, Extension] = {}

    def scan(self, root: PackageSpec) -> Extension:
        """Read a package, and its npm dependencies down to the requested depth."""
        first = self.read(root, history=True)
        queue: deque = deque((name, version, 1) for name, version in first.dependencies.items())
        skipped = 0
        while queue:
            name, requested, level = queue.popleft()
            if level > self.depth or root.ecosystem != NPM:
                skipped += 1
                continue
            if len(self.results) >= self.max_packages:
                skipped += 1 + len(queue)
                break
            spec = packages.parse_npm(f"{name}@{requested}") if _is_plain_range(requested) else None
            if spec is None:
                first.gap(f"dependency {name}", f"'{requested[:60]}' is not a registry version")
                continue
            try:
                extension = self.read(spec, history=False)
            except RegistryError as exc:
                first.gap(f"dependency {name}", str(exc))
                continue
            queue.extend((n, v, level + 1) for n, v in extension.dependencies.items())
        if skipped:
            first.gap("dependencies", f"{skipped} were not scanned; they run too, so raise --depth to include them")
        return first

    def read(self, spec: PackageSpec, history: bool) -> Extension:
        try:
            return self._read_npm(spec, history) if spec.ecosystem == NPM else self._read_pypi(spec)
        except (TypeError, AttributeError, KeyError, IndexError, ValueError) as exc:
            # A response in an unexpected shape must not end the rest of the scan.
            raise RegistryError(f"the registry sent an unexpected response ({type(exc).__name__})") from exc

    def _json(self, url: str, limit: int, headers: dict | None = None) -> dict:
        try:
            data = json.loads(self.fetcher.get(url, limit, headers))
        except (ValueError, RecursionError) as exc:
            raise RegistryError("the registry sent something that is not valid JSON") from exc
        if not isinstance(data, dict):
            raise RegistryError("the registry sent an unexpected response")
        return data

    def _npm_target(self, spec: PackageSpec) -> str:
        requested = spec.requested or "latest"
        if spec.exact or URL_SAFE_VERSION.match(requested) and not requested[0].isdigit():
            return requested.removeprefix("v")
        document = self._json(f"{NPM_REGISTRY}/{spec.name}", MAX_PACKUMENT, ABBREVIATED)
        versions = document.get("versions")
        best = packages.max_satisfying(list(versions) if isinstance(versions, dict) else [], requested)
        if best is None:
            raise RegistryError(f"no published version matches '{requested[:40]}'")
        return best

    def _read_npm(self, spec: PackageSpec, history: bool) -> Extension:
        target = self._npm_target(spec)
        document = self._json(f"{NPM_REGISTRY}/{spec.name}/{target}", MAX_DOCUMENT)
        version = str(document.get("version") or target)
        key = f"npm:{spec.name}@{version}"
        if key in self.results:
            return self.results[key]
        extension = Extension(name=spec.name, kind=NPM, location=key, version=version)
        self.results[key] = extension
        dist = document.get("dist") if isinstance(document.get("dist"), dict) else {}
        url = str(dist.get("tarball") or "")
        if not self._allowed(extension, url, NPM_DOWNLOAD_HOSTS):
            return extension
        data = self.fetcher.get(url, MAX_DOWNLOAD)
        _verify_npm(extension, data, dist)
        read_tarball(extension, data)
        loaders.parse_declarations(extension)
        analyzers.analyze(extension)
        self._npm_signals(extension, document, dist)
        if history:
            self._npm_history(extension, spec, version)
        return extension

    def _allowed(self, extension: Extension, url: str, hosts: set[str]) -> bool:
        host = urlsplit(url).hostname
        if host in hosts:
            return True
        extension.finding(
            "supply.unexpected-download-host", "backdoor", Severity.HIGH,
            f"The registry points the download at {str(host)[:60]}",
            "Packages should come from the registry's own file host. The code was not fetched.",
            "registry",
        )
        extension.gap("package code", "the download address looked wrong, so nothing was read")
        return False

    def _npm_signals(self, extension: Extension, document: dict, dist: dict) -> None:
        supply.lookalike(extension, "registry", extension.name)
        if document.get("deprecated"):
            extension.finding(
                "supply.deprecated", "opsec", Severity.MEDIUM,
                "This version is marked deprecated",
                f"The maintainer says: {str(document['deprecated'])[:120]}", "registry",
            )
        if not dist.get("attestations"):
            extension.finding(
                "supply.no-provenance", "opsec", Severity.INFO,
                "No signed record of where this release was built",
                "Provenance links a release to its source and build. Many honest packages lack it.",
                "registry",
            )
        _manifest_confusion(extension, document)

    def _npm_history(self, extension: Extension, spec: PackageSpec, version: str) -> None:
        try:
            document = self._json(f"{NPM_REGISTRY}/{spec.name}", MAX_PACKUMENT)
        except RegistryError:
            extension.gap("release history", "could not be read, so release age and publisher were not checked")
            return
        times = document.get("time") if isinstance(document.get("time"), dict) else {}
        self._age(extension, _when(times.get(version)), _when(times.get("created")))
        versions = document.get("versions") if isinstance(document.get("versions"), dict) else {}
        dated = sorted(
            (stamp, name) for name, stamp in ((n, _when(times.get(n))) for n in versions) if stamp is not None
        )
        ordered = [name for _, name in dated]
        if version in ordered and ordered.index(version) > 0:
            previous = ordered[ordered.index(version) - 1]
            now_by = _publisher(versions.get(version))
            then_by = _publisher(versions.get(previous))
            if now_by and then_by and now_by != then_by:
                extension.finding(
                    "supply.new-publisher", "backdoor", Severity.MEDIUM,
                    f"This release was published by a different account than {previous}",
                    f"{then_by[:40]} published the last one and {now_by[:40]} published this one. "
                    "A sudden change of publisher is how account takeovers often look.",
                    "registry",
                )

    def _age(self, extension: Extension, released: datetime | None, created: datetime | None) -> None:
        if released and self.now - released < timedelta(days=FRESH_RELEASE_DAYS):
            days = max((self.now - released).days, 0)
            extension.finding(
                "supply.fresh-release", "opsec", Severity.MEDIUM,
                f"This version is only {days} day(s) old",
                "Hijacked releases are usually caught within days. Waiting a week avoids most of them.",
                "registry", fix="Pin the previous version until this one has aged.",
            )
        if created and self.now - created < timedelta(days=NEW_PACKAGE_DAYS):
            extension.finding(
                "supply.new-package", "opsec", Severity.MEDIUM,
                "This package is less than a month old",
                "New packages have no track record, and lookalike attacks rely on that.",
                "registry",
            )

    def _read_pypi(self, spec: PackageSpec) -> Extension:
        name = spec.name
        version = spec.requested if spec.exact and URL_SAFE_VERSION.match(spec.requested) else ""
        url = f"{PYPI_REGISTRY}/pypi/{name}/{version}/json" if version else f"{PYPI_REGISTRY}/pypi/{name}/json"
        document = self._json(url, MAX_PACKUMENT)
        info = document.get("info") if isinstance(document.get("info"), dict) else {}
        version = str(info.get("version") or version)
        key = f"pypi:{name}@{version}"
        if key in self.results:
            return self.results[key]
        extension = Extension(name=name, kind=PYPI, location=key, version=version)
        self.results[key] = extension
        if spec.requested and not spec.exact:
            extension.gap("version", f"'{spec.requested[:40]}' is a range; the newest release was read")
        files = [f for f in document.get("urls") or [] if isinstance(f, dict)]
        chosen = _choose_file(files)
        if chosen is None:
            extension.gap("package code", "the release lists no files to read")
            return extension
        file_url = str(chosen.get("url") or "")
        if not self._allowed(extension, file_url, PYPI_DOWNLOAD_HOSTS):
            return extension
        data = self.fetcher.get(file_url, MAX_DOWNLOAD)
        _verify_digest(extension, data, "sha256", str((chosen.get("digests") or {}).get("sha256") or ""))
        if str(chosen.get("filename", "")).endswith((".whl", ".zip")):
            _read_wheel(extension, data)
            if "none-any" not in str(chosen.get("filename")):
                extension.gap("other builds", f"only {str(chosen.get('filename'))[:80]} was read; other platforms get different files")
        else:
            read_tarball(extension, data)
            extension.gap("build step", "this release is a source package, and installing it runs its build code")
        loaders.parse_declarations(extension)
        analyzers.analyze(extension)
        self._pypi_signals(extension, document, info, chosen)
        return extension

    def _pypi_signals(self, extension: Extension, document: dict, info: dict, chosen: dict) -> None:
        supply.lookalike(extension, "registry", extension.name)
        if info.get("yanked") or chosen.get("yanked"):
            extension.finding(
                "supply.yanked", "backdoor", Severity.HIGH,
                "This release was withdrawn from PyPI",
                f"Reason given: {str(info.get('yanked_reason') or 'none')[:120]}", "registry",
            )
        for advisory in (document.get("vulnerabilities") or [])[:20]:
            if isinstance(advisory, dict) and not advisory.get("withdrawn"):
                extension.finding(
                    "supply.known-vulnerability", "opsec", Severity.HIGH,
                    f"Known vulnerability: {str(advisory.get('id') or 'unlisted')[:40]}",
                    str(advisory.get("summary") or advisory.get("details") or "")[:200], "registry",
                    fix=f"Fixed in: {', '.join(str(v) for v in (advisory.get('fixed_in') or [])[:4]) or 'not stated'}",
                )
        self._age(extension, _when(chosen.get("upload_time_iso_8601")), _first_release(document))
        required = info.get("requires_dist")
        if isinstance(required, list) and required:
            extension.gap("dependencies", f"{len(required)} declared dependencies were not scanned")


def expand(extensions: list[Extension], client: Client) -> list[Extension]:
    """Read the package behind every server that fetches one at launch."""
    for extension in list(extensions):
        for server in extension.servers:
            subject = f"server {server.name}"
            spec, reason = packages.from_command(server.command, server.args)
            if spec is None:
                if reason:
                    extension.gap(subject, reason)
                continue
            try:
                package = client.scan(spec)
            except RegistryError as exc:
                extension.gap(subject, f"could not read {str(spec)[:80]}: {exc}")
                continue
            extension.clear_gap(subject)
            if not spec.exact:
                extension.gap(subject, f"read {package.location} as published today; this unpinned command can fetch a different version at any start")
    return list(client.results.values())


def read_tarball(extension: Extension, data: bytes) -> None:
    """Unpack a .tgz in memory. The whole tar is inflated first so its size is known."""
    decompressor = zlib.decompressobj(31)
    try:
        raw = decompressor.decompress(data, loaders.MAX_PACKAGE_BYTES)
    except zlib.error:
        extension.gap("package code", "the archive could not be decompressed")
        return
    if decompressor.unconsumed_tail:
        extension.finding(
            "package.oversized", "backdoor", Severity.MEDIUM,
            "The package expands far beyond the size limit",
            "Nothing past the limit was read, so hidden files may exist.", "registry",
        )
        extension.gap("package code", "the archive is too large to read completely")
        return
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for count, member in enumerate(archive):
                if count >= loaders.MAX_FILES:
                    extension.gap("package code", f"stopped after {loaders.MAX_FILES} files")
                    break
                _read_member(extension, archive, member)
    except (tarfile.TarError, EOFError, ValueError, OSError):
        extension.gap("package code", "the archive is damaged, so it could not be read completely")


def _read_member(extension: Extension, archive: tarfile.TarFile, member: tarfile.TarInfo) -> None:
    path = PurePosixPath(member.name.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts:
        extension.finding(
            "package.path-traversal", "backdoor", Severity.HIGH,
            "Archive entry points outside the package",
            "An unsafe unpacker would write this file somewhere else on disk.",
            member.name[:200],
        )
        return
    if member.issym() or member.islnk():
        extension.finding(
            "package.symlink", "backdoor", Severity.HIGH,
            "Archive contains a link",
            "A link can redirect reads or writes to files outside the package.",
            member.name[:200],
        )
        return
    if not member.isfile() or len(path.parts) < 2:
        return
    relative = PurePosixPath(*path.parts[1:]).as_posix()  # drop package/ or name-1.2.3/
    if member.size > loaders.MAX_FILE_BYTES and path.suffix.lower() not in loaders.ASSET_SUFFIXES:
        extension.gap(relative, f"file is {member.size // 1024} KB, over the size limit")
        return
    handle = archive.extractfile(member)
    if handle is not None:
        loaders.add_entry(extension, relative, handle.read(loaders.MAX_FILE_BYTES))


def _read_wheel(extension: Extension, data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            loaders.read_archive(archive, extension)
    except zipfile.BadZipFile:
        extension.gap("package code", "the wheel is damaged, so it could not be read")


def _verify_npm(extension: Extension, data: bytes, dist: dict) -> None:
    integrity = str(dist.get("integrity") or "")
    algorithm, _, encoded = integrity.partition("-")
    if algorithm in {"sha512", "sha384", "sha256"} and encoded:
        try:
            expected = base64.b64decode(encoded).hex()
        except (binascii.Error, ValueError):
            expected = "unreadable"
        _verify_digest(extension, data, algorithm, expected)
    else:
        _verify_digest(extension, data, "sha1", str(dist.get("shasum") or ""))


def _verify_digest(extension: Extension, data: bytes, algorithm: str, expected: str) -> None:
    if not expected:
        extension.gap("integrity", "the registry gave no hash, so the download could not be verified")
    elif hashlib.new(algorithm, data).hexdigest() != expected.lower():
        extension.finding(
            "package.integrity-mismatch", "backdoor", Severity.CRITICAL,
            "The download does not match the registry's hash",
            "The file changed somewhere between the registry and this machine.", "registry",
        )


def _manifest_confusion(extension: Extension, document: dict) -> None:
    """Compare the registry's record with the package.json actually inside the archive.

    They are stored separately and can disagree. Installers run the scripts in the
    archive, while people and tools often read only the registry's copy.
    """
    file = extension.file("package.json")
    if file is None:
        return
    try:
        packed = json.loads(file.text)
    except (ValueError, RecursionError):
        return
    if not isinstance(packed, dict):
        return
    listed_scripts = document.get("scripts") if isinstance(document.get("scripts"), dict) else {}
    packed_scripts = packed.get("scripts") if isinstance(packed.get("scripts"), dict) else {}
    for name in LIFECYCLE:
        listed, inside = listed_scripts.get(name), packed_scripts.get(name)
        if listed != inside and "node-gyp" not in f"{listed}{inside}":
            _confused(extension, f"The '{name}' script differs from the registry's record")
    listed_dependencies = document.get("dependencies") if isinstance(document.get("dependencies"), dict) else {}
    packed_dependencies = packed.get("dependencies") if isinstance(packed.get("dependencies"), dict) else {}
    extra = sorted(set(packed_dependencies) ^ set(listed_dependencies))
    if extra:
        _confused(extension, f"Dependencies differ from the registry's record: {', '.join(extra[:4])[:100]}")


def _confused(extension: Extension, title: str) -> None:
    extension.finding(
        "supply.manifest-confusion", "backdoor", Severity.HIGH, title,
        "The package page and the code that installs do not agree. Trust neither until you know why.",
        "package.json",
    )


def _choose_file(files: list[dict]) -> dict | None:
    """Prefer what uvx installs: a universal wheel, then any wheel, then the source package."""
    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
    universal = [f for f in wheels if "none-any" in str(f.get("filename"))]
    sources = [f for f in files if f.get("packagetype") == "sdist"]
    return next(iter(universal or wheels or sources), None)


def _is_plain_range(requested: str) -> bool:
    return bool(requested) and ":" not in requested and "/" not in requested


def _publisher(version: object) -> str:
    user = version.get("_npmUser") if isinstance(version, dict) else None
    return str(user.get("name") or "") if isinstance(user, dict) else ""


def _when(text: object) -> datetime | None:
    if not isinstance(text, str):
        return None
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _first_release(document: dict) -> datetime | None:
    releases = document.get("releases")
    if not isinstance(releases, dict):
        return None
    stamps = [
        _when(file.get("upload_time_iso_8601"))
        for files in releases.values() if isinstance(files, list)
        for file in files if isinstance(file, dict)
    ]
    return min((stamp for stamp in stamps if stamp), default=None)
