"""Online package reading. Nothing here touches the real internet.

Most tests use a fake registry. The Fetcher tests use a server on 127.0.0.1, so the real
HTTP path, including redirects and size limits, runs without leaving this machine.
"""

import base64
import contextlib
import gzip
import hashlib
import http.server
import io
import json
import tarfile
import tempfile
import threading
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from extaudit import chains, cli, registry, snapshot
from extaudit.model import Extension, ServerDecl, Severity
from extaudit.packages import PackageSpec, from_command, max_satisfying, parse_npm, parse_pypi, parse_spec

from .helpers import rules, worst, write_tree

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
OLD = "2025-01-01T00:00:00.000Z"
SHELL_SERVER = (
    'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\n'
    'import { exec } from "child_process";\n'
    'server.tool("run", {}, async ({ cmd }) => { exec(cmd); });\n'
)


def tgz(files: dict[str, str | bytes], root: str = "package") -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class FakeRegistry:
    """Serves the same shapes as npm and PyPI, as confirmed against the live APIs."""

    def __init__(self):
        self.pages: dict[str, bytes] = {}
        self.requests: list[str] = []

    def get(self, url: str, limit: int, headers=None) -> bytes:
        self.requests.append(url)
        if url not in self.pages:
            raise registry.NotFound("not found on the registry")
        return self.pages[url]

    def add_npm(self, name, versions: dict, *, latest=None, created=OLD, integrity=None, host="registry.npmjs.org", deprecated=None, listed_scripts=None):
        documents = {}
        times = {"created": created, "modified": OLD}
        for version, spec in versions.items():
            files = dict(spec.get("files", {"index.js": "// ok\n"}))
            dependencies = spec.get("dependencies", {})
            manifest = {"name": name, "version": version, "dependencies": dependencies, "scripts": spec.get("scripts", {})}
            files.setdefault("package.json", json.dumps(manifest))
            data = tgz(files)
            short = name.rsplit("/", 1)[-1]
            url = f"https://{host}/{name}/-/{short}-{version}.tgz"
            document = {
                "name": name, "version": version, "dependencies": dependencies,
                "scripts": listed_scripts if listed_scripts is not None else spec.get("scripts", {}),
                "_npmUser": {"name": spec.get("publisher", "maintainer")},
                "dist": {
                    "tarball": url, "integrity": integrity or sri(data), "fileCount": len(files),
                    "unpackedSize": len(data), "attestations": spec.get("attestations", {"url": "x"}),
                },
            }
            if deprecated:
                document["deprecated"] = deprecated
            self.pages[url] = data
            self.pages[f"https://registry.npmjs.org/{name}/{version}"] = json.dumps(document).encode()
            documents[version] = document
            times[version] = spec.get("published", OLD)
        latest = latest or list(versions)[-1]
        self.pages[f"https://registry.npmjs.org/{name}/latest"] = json.dumps(documents[latest]).encode()
        self.pages[f"https://registry.npmjs.org/{name}"] = json.dumps(
            {"name": name, "dist-tags": {"latest": latest}, "versions": documents, "time": times}
        ).encode()

    def add_pypi(self, name, version, files: dict[str, bytes], info=None, vulnerabilities=None):
        entries = []
        for filename, data in files.items():
            url = f"https://files.pythonhosted.org/packages/ab/cd/{filename}"
            self.pages[url] = data
            entries.append({
                "filename": filename, "url": url, "size": len(data), "yanked": False,
                "packagetype": "bdist_wheel" if filename.endswith(".whl") else "sdist",
                "digests": {"sha256": hashlib.sha256(data).hexdigest()},
                "upload_time_iso_8601": OLD,
            })
        document = {
            "info": {"version": version, "yanked": False, "requires_dist": [], **(info or {})},
            "urls": entries, "releases": {version: entries}, "vulnerabilities": vulnerabilities or [],
        }
        body = json.dumps(document).encode()
        self.pages[f"https://pypi.org/pypi/{name}/json"] = body
        self.pages[f"https://pypi.org/pypi/{name}/{version}/json"] = body


def wheel(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    return buffer.getvalue()


def client(fake: FakeRegistry, **options) -> registry.Client:
    return registry.Client(fake, now=NOW, **options)


class Specs(unittest.TestCase):
    def test_npm_forms(self):
        self.assertEqual(parse_npm("left-pad"), PackageSpec("npm", "left-pad"))
        self.assertEqual(parse_npm("left-pad@1.3.0"), PackageSpec("npm", "left-pad", "1.3.0", True))
        self.assertEqual(parse_npm("@a/b@latest"), PackageSpec("npm", "@a/b", "latest"))
        self.assertEqual(parse_npm("@a/b@^1.2.0"), PackageSpec("npm", "@a/b", "^1.2.0"))

    def test_pypi_forms(self):
        self.assertEqual(parse_pypi("mcp-server-git"), PackageSpec("pypi", "mcp-server-git"))
        self.assertEqual(parse_pypi("pkg==1.2"), PackageSpec("pypi", "pkg", "1.2", True))
        self.assertEqual(parse_pypi("pkg@1.2"), PackageSpec("pypi", "pkg", "1.2", True))
        self.assertEqual(parse_pypi("pkg[extra]==1.2"), PackageSpec("pypi", "pkg", "1.2", True))
        self.assertEqual(parse_pypi("pkg>=1.2"), PackageSpec("pypi", "pkg", ">=1.2"))
        self.assertEqual(parse_pypi("pkg@latest"), PackageSpec("pypi", "pkg"))

    def test_hostile_names_cannot_reach_a_url(self):
        for text in ("../../evil", "a/../b", "@a/../../b", "https://evil.example/x.tgz", "git+https://x/y",
                     "file:../x", "./local", "/abs/path", "a b", "a?x=1", "a#b", "a%2fb"):
            self.assertIsNone(parse_npm(text), text)
        for text in ("../evil", "git+https://x/y", "https://x/y.whl", "./local", "a/b", "a b"):
            self.assertIsNone(parse_pypi(text), text)

    def test_named_on_the_command_line(self):
        self.assertEqual(parse_spec("npm:a@1.0.0").name, "a")
        self.assertEqual(parse_spec("pypi:a==1.0").ecosystem, "pypi")
        self.assertEqual(parse_spec("a").ecosystem, "npm")

    def test_runners(self):
        cases = [
            ("npx", ["-y", "pkg@1.0.0"], "npm", "pkg"),
            ("npx.cmd", ["--yes", "@a/b"], "npm", "@a/b"),
            ("C:\\node\\npx.cmd", ["-y", "pkg"], "npm", "pkg"),
            ("npx", ["-y", "-p", "real", "cmd"], "npm", "real"),
            ("npx", ["--package=real", "cmd"], "npm", "real"),
            ("bunx", ["pkg"], "npm", "pkg"),
            ("pnpm", ["dlx", "pkg"], "npm", "pkg"),
            ("yarn", ["dlx", "pkg"], "npm", "pkg"),
            ("npm", ["exec", "pkg"], "npm", "pkg"),
            ("uvx", ["pkg"], "pypi", "pkg"),
            ("uvx", ["--from", "real", "cmd"], "pypi", "real"),
            ("uvx", ["--python", "3.12", "pkg"], "pypi", "pkg"),
            ("pipx", ["run", "pkg"], "pypi", "pkg"),
            ("uv", ["tool", "run", "pkg"], "pypi", "pkg"),
        ]
        for command, args, ecosystem, name in cases:
            spec, reason = from_command(command, args)
            self.assertEqual((spec.ecosystem, spec.name, reason), (ecosystem, name, ""), (command, args))

    def test_not_a_runner(self):
        self.assertEqual(from_command("node", ["a.js"]), (None, ""))
        self.assertEqual(from_command("docker", ["run", "x"]), (None, ""))

    def test_things_a_registry_cannot_answer(self):
        spec, reason = from_command("uvx", ["--from", "git+https://github.com/a/b", "cmd"])
        self.assertIsNone(spec)
        self.assertIn("not a registry package", reason)
        spec, reason = from_command("npx", ["--registry", "https://npm.example.net", "pkg"])
        self.assertIsNone(spec)
        self.assertIn("custom package source", reason)
        self.assertIn("names no package", from_command("npx", ["-y"])[1])


class VersionRanges(unittest.TestCase):
    PUBLISHED = ["0.9.0", "1.0.0", "1.2.3", "1.2.9", "1.9.0", "2.0.0", "2.1.0-beta.1", "3.0.0"]

    def test_ranges(self):
        for expression, expected in {
            "^1.2.3": "1.9.0", "~1.2.3": "1.2.9", "1.2.3": "1.2.3", "*": "3.0.0", "": "3.0.0",
            "1.x": "1.9.0", "1": "1.9.0", "1.2": "1.2.9", ">=1.0.0 <2.0.0": "1.9.0",
            ">=2": "3.0.0", "<1.0.0": "0.9.0", "^0.9.0": "0.9.0", "1.0.0 - 1.2.3": "1.2.3",
            "^2.0.0 || ^3.0.0": "3.0.0", ">= 1.2.3 < 1.3.0": "1.2.9",
        }.items():
            self.assertEqual(max_satisfying(self.PUBLISHED, expression), expected, expression)

    def test_caret_below_one(self):
        self.assertEqual(max_satisfying(["0.2.3", "0.2.9", "0.3.0"], "^0.2.3"), "0.2.9")
        self.assertEqual(max_satisfying(["0.0.3", "0.0.4"], "^0.0.3"), "0.0.3")

    def test_prereleases_are_skipped(self):
        self.assertEqual(max_satisfying(["1.0.0", "1.1.0-rc.1"], "^1.0.0"), "1.0.0")

    def test_nothing_matches(self):
        self.assertIsNone(max_satisfying(self.PUBLISHED, "^9.0.0"))
        self.assertIsNone(max_satisfying(self.PUBLISHED, "not a range"))


class ReadingNpm(unittest.TestCase):
    def test_finds_problems_inside_the_published_code(self):
        fake = FakeRegistry()
        fake.add_npm("shell-mcp", {"1.0.0": {"files": {"index.js": SHELL_SERVER}}})
        extension = client(fake).scan(PackageSpec("npm", "shell-mcp"))
        self.assertEqual((extension.kind, extension.version), ("npm", "1.0.0"))
        self.assertEqual(extension.location, "npm:shell-mcp@1.0.0")
        self.assertEqual(worst(extension, "input.command-injection"), Severity.CRITICAL)

    def test_exact_version_uses_that_version(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}, "2.0.0": {}})
        self.assertEqual(client(fake).scan(PackageSpec("npm", "a", "1.0.0", True)).version, "1.0.0")

    def test_a_range_picks_what_npm_would(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}, "1.5.0": {}, "2.0.0": {}})
        self.assertEqual(client(fake).scan(parse_npm("a@^1.0.0")).version, "1.5.0")

    def test_scoped_name_goes_in_the_path_as_npm_serves_it(self):
        fake = FakeRegistry()
        fake.add_npm("@acme/tool", {"1.0.0": {}})
        client(fake).scan(parse_npm("@acme/tool"))
        self.assertIn("https://registry.npmjs.org/@acme/tool/latest", fake.requests)

    def test_install_scripts_in_the_archive_are_reported(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"scripts": {"postinstall": "node setup.js"}}})
        self.assertIn("supply.install-script", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_files_are_not_written_anywhere(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        with tempfile.TemporaryDirectory() as folder, contextlib.chdir(folder):
            client(fake).scan(PackageSpec("npm", "a"))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_missing_package_is_an_error_to_report_not_a_crash(self):
        with self.assertRaises(registry.NotFound):
            client(FakeRegistry()).scan(PackageSpec("npm", "missing"))

    def test_published_packages_are_not_asked_for_a_lockfile(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"dependencies": {"b": "1.0.0"}}})
        self.assertNotIn("supply.no-lockfile", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_odd_response_shapes_become_errors_not_crashes(self):
        def survives(fake: FakeRegistry, spec: PackageSpec) -> None:
            try:
                client(fake).scan(spec)
            except registry.RegistryError:
                pass  # anything else fails the test

        for body in (b"[]", b"5", b"not json", b'{"dist": 5}', b'{"dist": {"tarball": 7}}', b'{"version": {}}'):
            fake = FakeRegistry()
            fake.pages["https://registry.npmjs.org/a/latest"] = body
            survives(fake, PackageSpec("npm", "a"))
        for body in (b'{"urls": 5}', b'{"info": 5, "urls": [{"packagetype": 3}]}',
                     b'{"urls": [{"url": 5, "packagetype": "sdist"}], "vulnerabilities": {"a": 1}}'):
            fake = FakeRegistry()
            fake.pages["https://pypi.org/pypi/a/json"] = body
            survives(fake, PackageSpec("pypi", "a"))


class Tampering(unittest.TestCase):
    def test_hash_mismatch(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}}, integrity=sri(b"something else"))
        self.assertEqual(worst(client(fake).scan(PackageSpec("npm", "a")), "package.integrity-mismatch"), Severity.CRITICAL)

    def test_correct_hash_is_quiet(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        self.assertNotIn("package.integrity-mismatch", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_download_on_another_host_is_refused(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}}, host="cdn.evil.example")
        extension = client(fake).scan(PackageSpec("npm", "a"))
        self.assertEqual(worst(extension, "supply.unexpected-download-host"), Severity.HIGH)
        self.assertFalse([url for url in fake.requests if "evil" in url])

    def test_scripts_hidden_from_the_registry_record(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"scripts": {"postinstall": "node x.js"}}}, listed_scripts={})
        self.assertEqual(worst(client(fake).scan(PackageSpec("npm", "a")), "supply.manifest-confusion"), Severity.HIGH)

    def test_dependencies_hidden_from_the_registry_record(self):
        fake = FakeRegistry()
        inner = json.dumps({"name": "a", "version": "1.0.0", "dependencies": {"hidden": "1.0.0"}})
        fake.add_npm("a", {"1.0.0": {"files": {"index.js": "//\n", "package.json": inner}}})
        self.assertIn("supply.manifest-confusion", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_node_gyp_default_is_not_confusion(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}}, listed_scripts={"install": "node-gyp rebuild"})
        self.assertNotIn("supply.manifest-confusion", rules(client(fake).scan(PackageSpec("npm", "a"))))


class HostileArchives(unittest.TestCase):
    def read(self, data: bytes):
        extension = registry.Extension(name="x", kind="npm", location="x")
        registry.read_tarball(extension, data)
        return extension

    def test_path_escape_is_flagged_and_dropped(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/../../evil.js")
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
        extension = self.read(buffer.getvalue())
        self.assertEqual(worst(extension, "package.path-traversal"), Severity.HIGH)
        self.assertFalse(extension.files)

    def test_links_are_flagged_and_dropped(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            info = tarfile.TarInfo("package/link")
            info.type = tarfile.SYMTYPE
            info.linkname = "/etc/passwd"
            archive.addfile(info)
        extension = self.read(buffer.getvalue())
        self.assertIn("package.symlink", rules(extension))
        self.assertFalse(extension.files)

    def test_decompression_bomb_stops_at_the_limit(self):
        with mock.patch.object(registry.loaders, "MAX_PACKAGE_BYTES", 1024 * 1024):
            extension = self.read(gzip.compress(b"\0" * (8 * 1024 * 1024)))
        self.assertIn("package.oversized", rules(extension))

    def test_damaged_archives_are_gaps(self):
        self.assertTrue(self.read(b"not gzip at all").gaps)
        self.assertTrue(self.read(gzip.compress(b"not a tar file" * 100)).gaps)

    def test_vendored_code_inside_a_package(self):
        data = tgz({"index.js": "// ok\n", "node_modules/dep/index.js": 'require("child_process").exec("id");\n'})
        extension = self.read(data)
        self.assertEqual([f.path for f in extension.files], ["index.js"])
        self.assertEqual(extension.vendored_files, 1)


class Signals(unittest.TestCase):
    def days_ago(self, days: int) -> str:
        return (NOW - timedelta(days=days)).isoformat().replace("+00:00", "Z")

    def test_fresh_release(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}, "1.0.1": {"published": self.days_ago(2)}})
        finding = next(f for f in client(fake).scan(PackageSpec("npm", "a")).findings if f.rule == "supply.fresh-release")
        self.assertIn("2 day", finding.title)

    def test_aged_release_is_quiet(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        self.assertNotIn("supply.fresh-release", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_new_package(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}}, created=self.days_ago(5))
        self.assertIn("supply.new-package", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_change_of_publisher(self):
        fake = FakeRegistry()
        fake.add_npm("a", {
            "1.0.0": {"publisher": "alice", "published": "2025-01-01T00:00:00Z"},
            "1.0.1": {"publisher": "mallory", "published": "2025-06-01T00:00:00Z"},
        })
        finding = next(f for f in client(fake).scan(PackageSpec("npm", "a")).findings if f.rule == "supply.new-publisher")
        self.assertIn("mallory", finding.detail)

    def test_same_publisher_is_quiet(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"published": "2025-01-01T00:00:00Z"}, "1.0.1": {"published": "2025-06-01T00:00:00Z"}})
        self.assertNotIn("supply.new-publisher", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_deprecated(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}}, deprecated="use b instead")
        self.assertIn("supply.deprecated", rules(client(fake).scan(PackageSpec("npm", "a"))))

    def test_lookalike_name(self):
        fake = FakeRegistry()
        fake.add_npm("expresss", {"1.0.0": {}})
        self.assertEqual(worst(client(fake).scan(PackageSpec("npm", "expresss")), "supply.lookalike-package"), Severity.HIGH)

    def test_unreadable_history_is_a_gap(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        del fake.pages["https://registry.npmjs.org/a"]
        extension = client(fake).scan(PackageSpec("npm", "a"))
        self.assertTrue(any(g.subject == "release history" for g in extension.gaps))


class Dependencies(unittest.TestCase):
    def tree(self) -> FakeRegistry:
        fake = FakeRegistry()
        fake.add_npm("root", {"1.0.0": {"dependencies": {"child": "^1.0.0"}}})
        fake.add_npm("child", {"1.0.0": {}, "1.2.0": {"dependencies": {"grandchild": "1.0.0"}}})
        fake.add_npm("grandchild", {"1.0.0": {"files": {"index.js": 'require("child_process").exec("id");\n'}}})
        return fake

    def test_depth_zero_says_what_it_skipped(self):
        fake = self.tree()
        reader = client(fake)
        extension = reader.scan(PackageSpec("npm", "root"))
        self.assertEqual(list(reader.results), ["npm:root@1.0.0"])
        self.assertTrue(any("raise --depth" in g.reason for g in extension.gaps))

    def test_depth_follows_the_version_npm_would_pick(self):
        reader = client(self.tree(), depth=2)
        reader.scan(PackageSpec("npm", "root"))
        self.assertEqual(set(reader.results), {"npm:root@1.0.0", "npm:child@1.2.0", "npm:grandchild@1.0.0"})

    def test_a_cycle_ends(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"dependencies": {"b": "1.0.0"}}})
        fake.add_npm("b", {"1.0.0": {"dependencies": {"a": "1.0.0"}}})
        reader = client(fake, depth=9)
        reader.scan(PackageSpec("npm", "a"))
        self.assertEqual(len(reader.results), 2)

    def test_package_limit(self):
        fake = FakeRegistry()
        names = {f"dep{i}": "1.0.0" for i in range(5)}
        fake.add_npm("root", {"1.0.0": {"dependencies": names}})
        for name in names:
            fake.add_npm(name, {"1.0.0": {}})
        reader = client(fake, depth=1, max_packages=3)
        extension = reader.scan(PackageSpec("npm", "root"))
        self.assertEqual(len(reader.results), 3)
        self.assertTrue(any("were not scanned" in g.reason for g in extension.gaps))

    def test_git_dependency_is_a_gap(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"dependencies": {"b": "github:evil/b"}}})
        extension = client(fake, depth=1).scan(PackageSpec("npm", "a"))
        self.assertTrue(any(g.subject == "dependency b" for g in extension.gaps))

    def test_broken_dependency_does_not_stop_the_scan(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"dependencies": {"gone": "1.0.0"}}})
        extension = client(fake, depth=1).scan(PackageSpec("npm", "a"))
        self.assertTrue(any(g.subject == "dependency gone" for g in extension.gaps))


class ReadingPypi(unittest.TestCase):
    SERVER = (
        "from mcp.server.fastmcp import FastMCP\nimport os\nmcp = FastMCP('x')\n"
        "@mcp.tool()\ndef run(cmd: str):\n    os.system(cmd)\n"
    )

    def test_reads_a_wheel(self):
        fake = FakeRegistry()
        fake.add_pypi("a-server", "1.0", {"a_server-1.0-py3-none-any.whl": wheel({"a_server/main.py": self.SERVER})})
        extension = client(fake).scan(PackageSpec("pypi", "a-server"))
        self.assertEqual((extension.kind, extension.version), ("pypi", "1.0"))
        self.assertEqual(worst(extension, "input.command-injection"), Severity.CRITICAL)

    def test_prefers_a_universal_wheel(self):
        fake = FakeRegistry()
        fake.add_pypi("a", "1.0", {
            "a-1.0.tar.gz": tgz({"x.py": "x = 1\n"}, root="a-1.0"),
            "a-1.0-cp312-win_amd64.whl": wheel({"native.py": "x = 1\n"}),
            "a-1.0-py3-none-any.whl": wheel({"pure.py": "x = 1\n"}),
        })
        self.assertEqual([f.path for f in client(fake).scan(PackageSpec("pypi", "a")).files], ["pure.py"])

    def test_platform_wheel_says_other_builds_differ(self):
        fake = FakeRegistry()
        fake.add_pypi("a", "1.0", {"a-1.0-cp312-win_amd64.whl": wheel({"a.py": "x = 1\n"})})
        self.assertTrue(any(g.subject == "other builds" for g in client(fake).scan(PackageSpec("pypi", "a")).gaps))

    def test_source_package_warns_about_its_build_step(self):
        fake = FakeRegistry()
        fake.add_pypi("a", "1.0", {"a-1.0.tar.gz": tgz({"setup.py": "import os\nos.system('id')\n"}, root="a-1.0")})
        extension = client(fake).scan(PackageSpec("pypi", "a"))
        self.assertIn("backdoor.install-time-code", rules(extension))
        self.assertTrue(any(g.subject == "build step" for g in extension.gaps))

    def test_hash_mismatch(self):
        fake = FakeRegistry()
        fake.add_pypi("a", "1.0", {"a-1.0-py3-none-any.whl": wheel({"a.py": "x = 1\n"})})
        url = "https://files.pythonhosted.org/packages/ab/cd/a-1.0-py3-none-any.whl"
        fake.pages[url] = wheel({"a.py": "x = 2\n"})
        self.assertEqual(worst(client(fake).scan(PackageSpec("pypi", "a")), "package.integrity-mismatch"), Severity.CRITICAL)

    def test_known_vulnerability_and_yanked(self):
        fake = FakeRegistry()
        fake.add_pypi(
            "a", "1.0", {"a-1.0-py3-none-any.whl": wheel({"a.py": "x = 1\n"})},
            info={"yanked": True, "yanked_reason": "bad"},
            vulnerabilities=[{"id": "GHSA-x", "summary": "RCE", "fixed_in": ["1.1"]}],
        )
        extension = client(fake).scan(PackageSpec("pypi", "a"))
        self.assertEqual(worst(extension, "supply.known-vulnerability"), Severity.HIGH)
        self.assertEqual(worst(extension, "supply.yanked"), Severity.HIGH)

    def test_withdrawn_advisory_is_ignored(self):
        fake = FakeRegistry()
        fake.add_pypi("a", "1.0", {"a-1.0-py3-none-any.whl": wheel({"a.py": "x = 1\n"})},
                      vulnerabilities=[{"id": "X", "withdrawn": "2025-01-01"}])
        self.assertNotIn("supply.known-vulnerability", rules(client(fake).scan(PackageSpec("pypi", "a"))))


def config_server(command: str, args: list[str], name: str = "s"):
    return Extension(name=name, kind="mcp-config", location="x", servers=[ServerDecl(name=name, command=command, args=args)])


class Expanding(unittest.TestCase):
    def test_gap_is_replaced_but_never_removed(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        extension = config_server("npx", ["-y", "a"])
        extension.gap("server s", "a is downloaded when it starts, so its code was not scanned")
        found = registry.expand([extension], client(fake))
        self.assertEqual(len(found), 1)
        self.assertEqual(len(extension.gaps), 1)
        self.assertIn("can fetch a different version", extension.gaps[0].reason)

    def test_pinned_command_closes_the_gap(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        extension = config_server("npx", ["-y", "a@1.0.0"])
        extension.gap("server s", "a is downloaded when it starts, so its code was not scanned")
        registry.expand([extension], client(fake))
        self.assertEqual(extension.gaps, [])

    def test_unreachable_package_leaves_a_gap(self):
        extension = config_server("npx", ["-y", "gone"])
        self.assertEqual(registry.expand([extension], client(FakeRegistry())), [])
        self.assertIn("could not read", extension.gaps[0].reason)

    def test_git_source_explains_itself(self):
        extension = config_server("uvx", ["--from", "git+https://github.com/a/b", "cmd"])
        registry.expand([extension], client(FakeRegistry()))
        self.assertIn("not a registry package", extension.gaps[0].reason)

    def test_same_package_twice_is_read_once(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        found = registry.expand([config_server("npx", ["a"], "one"), config_server("npx", ["a"], "two")], client(fake))
        self.assertEqual(len(found), 1)

    def test_package_code_feeds_attack_chains(self):
        fake = FakeRegistry()
        fake.add_npm("shell-mcp", {"1.0.0": {"files": {"index.js": SHELL_SERVER}}})
        extensions = [config_server("npx", ["shell-mcp"], "shell")]
        extensions.extend(registry.expand(extensions, client(fake)))
        mail = registry.Extension(name="gmail", kind="connector", location="x")
        mail.capability("untrusted_input", "declared")
        found = chains.find_chains([*extensions, mail])
        self.assertEqual(found[0].rule, "chain.injection-to-exec")
        self.assertEqual(found[0].severity, Severity.CRITICAL)


class UnpinnedUpdates(unittest.TestCase):
    def test_baseline_notices_latest_moving(self):
        before = FakeRegistry()
        before.add_npm("a", {"1.0.0": {}})
        after = FakeRegistry()
        after.add_npm("a", {"1.0.0": {}, "1.0.1": {"files": {"index.js": 'fetch("https://new.example.net/x");\n'}}})
        old = snapshot.build_set([client(before).scan(PackageSpec("npm", "a"))])
        new = snapshot.build_set([client(after).scan(PackageSpec("npm", "a"))])
        changed = {finding.rule for finding in snapshot.diff_sets(old, new)}
        self.assertTrue({"update.package-version", "update.new-host", "update.new-capability"} <= changed)


class Fetching(unittest.TestCase):
    """The real urllib path, against a server that never leaves this machine."""

    @classmethod
    def setUpClass(cls):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/ok":
                    self._send(200, b"hello")
                elif self.path == "/big":
                    self._send(200, b"x" * 5000)
                elif self.path == "/away":
                    self.send_response(302)
                    self.send_header("Location", "https://evil.example/x")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                elif self.path == "/ua":
                    self._send(200, self.headers.get("User-Agent", "").encode())
                elif self.path == "/teapot":
                    self._send(418, b"no")
                else:
                    self._send(404, b"missing")

            def _send(self, code, body):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def fetcher(self) -> registry.Fetcher:
        with mock.patch.dict("os.environ", {"NO_PROXY": "127.0.0.1"}):
            return registry.Fetcher({"127.0.0.1"}, allow_http=True, timeout=5)

    def test_reads_a_response(self):
        self.assertEqual(self.fetcher().get(f"{self.base}/ok", 100), b"hello")

    def test_identifies_itself_and_nothing_else(self):
        self.assertTrue(self.fetcher().get(f"{self.base}/ua", 100).startswith(b"extaudit/"))

    def test_size_limit(self):
        with self.assertRaises(registry.RegistryError):
            self.fetcher().get(f"{self.base}/big", 100)

    def test_redirect_to_another_host_is_refused(self):
        with self.assertRaises(registry.RegistryError) as caught:
            self.fetcher().get(f"{self.base}/away", 100)
        self.assertIn("evil.example", str(caught.exception))

    def test_not_found(self):
        with self.assertRaises(registry.NotFound):
            self.fetcher().get(f"{self.base}/nothing", 100)

    def test_other_errors(self):
        with self.assertRaises(registry.RegistryError):
            self.fetcher().get(f"{self.base}/teapot", 100)

    def test_unreachable_host(self):
        fetcher = registry.Fetcher({"127.0.0.1"}, allow_http=True, timeout=2)
        with self.assertRaises(registry.RegistryError):
            fetcher.get("http://127.0.0.1:1/x", 100)

    def test_default_client_only_speaks_https_to_known_hosts(self):
        fetcher = registry.Fetcher()
        # If the check ever fails, this stops at the mock rather than reaching the internet.
        with mock.patch.object(fetcher.opener, "open", side_effect=AssertionError("tried to connect")):
            for url in ("http://registry.npmjs.org/a", "https://evil.example/a", "file:///etc/passwd",
                        "ftp://pypi.org/a", "https://registry.npmjs.org.evil.example/a"):
                with self.assertRaises(registry.RegistryError) as caught:
                    fetcher.get(url, 100)
                self.assertIn("refused", str(caught.exception))


def run_cli(*args: str) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
        code = cli.main(list(args))
    return code, buffer.getvalue()


class CommandLine(unittest.TestCase):
    def test_nothing_touches_the_network_without_the_flag(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(registry.Fetcher, "get", side_effect=AssertionError("network used")):
            target = write_tree(Path(folder) / "t", {".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}}'})
            code, text = run_cli("scan", str(target), "--fail-on", "none")
        self.assertEqual(code, 0)
        self.assertIn("downloaded when it starts", text)

    def test_online_flag_reads_the_package(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"files": {"index.js": SHELL_SERVER}}})
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(registry, "Fetcher", return_value=fake):
            target = write_tree(Path(folder) / "t", {".mcp.json": '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}}'})
            code, text = run_cli("scan", str(target), "--online")
        self.assertEqual(code, 1)
        self.assertIn("input.command-injection", text)
        self.assertIn("Only package names and versions", text)

    def test_only_names_and_versions_reach_the_registry(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {}})
        config = {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a", "--token", "hunter2secret"], "env": {"KEY": "hunter2secret"}}}}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(registry, "Fetcher", return_value=fake):
            target = write_tree(Path(folder) / "t", {".mcp.json": json.dumps(config)})
            run_cli("scan", str(target), "--online", "--fail-on", "none")
        self.assertTrue(fake.requests)
        self.assertFalse([url for url in fake.requests if "hunter2" in url or "token" in url])

    def test_package_command(self):
        fake = FakeRegistry()
        fake.add_npm("a", {"1.0.0": {"files": {"index.js": SHELL_SERVER}}})
        with mock.patch.object(registry, "Fetcher", return_value=fake):
            code, text = run_cli("package", "npm:a@1.0.0", "--format", "json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(text)["extensions"][0]["kind"], "npm")

    def test_package_command_reports_failures(self):
        with mock.patch.object(registry, "Fetcher", return_value=FakeRegistry()):
            code, text = run_cli("package", "npm:missing")
        self.assertEqual(code, 2)
        self.assertIn("not found", text)

    def test_bad_name_is_refused_before_any_request(self):
        fake = FakeRegistry()
        with mock.patch.object(registry, "Fetcher", return_value=fake):
            code, _ = run_cli("package", "../../evil")
        self.assertEqual((code, fake.requests), (2, []))


if __name__ == "__main__":
    unittest.main()
