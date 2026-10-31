"""Command line interface. Exit codes: 0 clean below the threshold, 1 findings, 2 errors."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, analyzers, chains, discover, loaders, packages, registry, report, snapshot
from .model import NET, REACH_DECLARED, UNTRUSTED, Extension, Severity

SEVERITIES = [s.label for s in Severity]
ONLINE_NOTE = (
    "Read {count} package(s) from npm and PyPI into memory. Only package names and versions "
    "were sent, and nothing was installed, run or saved."
)
CONNECTOR_NOTE = (
    "Connectors on your claude.ai account are not stored on this machine, so chains that start "
    "from them cannot appear here. List yours with --connector, for example --connector gmail."
)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    arguments = _parser().parse_args(argv)
    try:
        return arguments.run(arguments)
    except (loaders.LoadError, registry.RegistryError) as exc:
        print(f"extaudit: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"extaudit: {exc}", file=sys.stderr)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="extaudit",
        description="Static security review for Claude extensions, plugins, skills and MCP servers. "
        "Nothing is run, imported or installed.",
    )
    parser.add_argument("--version", action="version", version=f"extaudit {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="review extensions at the given paths")
    scan.add_argument("paths", nargs="+", help=".mcpb file, plugin or skill folder, or config JSON")
    scan.add_argument("--chains", action="store_true", help="check for risky combinations across everything loaded")
    _add_online(scan)
    _add_output(scan)
    scan.set_defaults(run=_scan)

    installed = commands.add_parser("installed", help="review everything installed on this machine")
    installed.add_argument(
        "--connector", action="append", default=[], metavar="NAME",
        help="a connector on your claude.ai account, such as gmail (repeatable); these are not stored locally",
    )
    _add_project(installed)
    _add_online(installed)
    _add_output(installed)
    installed.set_defaults(run=_installed)

    package = commands.add_parser("package", help="read a published package before you add it (uses the network)")
    package.add_argument("specs", nargs="+", metavar="SPEC", help="such as npm:name@1.2.3 or pypi:name==1.2.3")
    package.add_argument("--depth", type=int, default=0, help="also read npm dependencies this many levels down")
    package.add_argument("--max-packages", type=int, default=registry.MAX_PACKAGES, help="stop after this many packages")
    _add_output(package)
    package.set_defaults(run=_package)

    compare = commands.add_parser("diff", help="report what changed between two versions")
    compare.add_argument("old")
    compare.add_argument("new")
    _add_output(compare)
    compare.set_defaults(run=_diff)

    baseline = commands.add_parser("baseline", help="save or check a record of what is installed")
    baseline.add_argument("action", choices=["save", "check"])
    baseline.add_argument("file", help="baseline JSON file")
    _add_project(baseline)
    _add_online(baseline)
    _add_output(baseline)
    baseline.set_defaults(run=_baseline)
    return parser


def _add_online(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--online", action="store_true",
        help="read packages that servers fetch at launch from npm and PyPI; sends package names to them",
    )
    parser.add_argument("--depth", type=int, default=0, help="with --online, also read npm dependencies this many levels down")
    parser.add_argument("--max-packages", type=int, default=registry.MAX_PACKAGES, help="with --online, stop after this many packages")


def _add_project(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project", action="append", type=Path, default=None,
        help="project folder to include (repeatable; defaults to the current folder)",
    )


def _add_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    parser.add_argument("--output", type=Path, help="write the report to a file")
    parser.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide lower findings in text output")
    parser.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="high", help="exit 1 at this severity or above")
    parser.add_argument("--ignore", action="append", default=[], metavar="RULE", help="skip a rule (repeatable)")


def _analyze(extensions: list[Extension]) -> list[Extension]:
    for extension in extensions:
        analyzers.analyze(extension)
    return extensions


def _load_all(paths: list[str]) -> list[Extension]:
    extensions: list[Extension] = []
    for path in paths:
        extensions.extend(loaders.load_path(path))
    return _analyze(extensions)


def _go_online(extensions: list[Extension], arguments: argparse.Namespace) -> list[str]:
    """Add the packages servers fetch at launch. Nothing touches the network without --online."""
    if not arguments.online:
        return []
    client = registry.Client(registry.Fetcher(), depth=arguments.depth, max_packages=arguments.max_packages)
    fetched = registry.expand(extensions, client)
    extensions.extend(fetched)
    return [ONLINE_NOTE.format(count=len(fetched))]


def _scan(arguments: argparse.Namespace) -> int:
    extensions = _load_all(arguments.paths)
    notes = _go_online(extensions, arguments)
    wants_chains = arguments.chains or len(arguments.paths) > 1 or arguments.online
    found = chains.find_chains(extensions) if wants_chains else []
    return _finish(report.Result(extensions, chains=found, notes=notes), arguments)


def _installed(arguments: argparse.Namespace) -> int:
    extensions, searched = discover.discover(projects=arguments.project)
    _analyze(extensions)
    notes = _go_online(extensions, arguments)
    extensions.extend(_connector(name) for name in arguments.connector)
    if not arguments.connector:
        notes.append(CONNECTOR_NOTE)
    result = report.Result(extensions, chains=chains.find_chains(extensions), searched=searched, notes=notes)
    return _finish(result, arguments)


def _package(arguments: argparse.Namespace) -> int:
    client = registry.Client(registry.Fetcher(), depth=arguments.depth, max_packages=arguments.max_packages)
    for text in arguments.specs:
        spec = packages.parse_spec(text)
        if spec is None:
            raise loaders.LoadError(f"'{text}' is not a package name")
        try:
            client.scan(spec)
        except registry.RegistryError as exc:
            raise registry.RegistryError(f"{spec}: {exc}") from exc
    extensions = list(client.results.values())
    return _finish(report.Result(extensions, notes=[ONLINE_NOTE.format(count=len(extensions))]), arguments)


def _connector(name: str) -> Extension:
    """Stand in for a claude.ai connector, which leaves nothing on disk to scan."""
    extension = Extension(name=name, kind="connector", location="claude.ai account")
    extension.capability(UNTRUSTED, REACH_DECLARED, note="connector you listed")
    extension.capability(NET, REACH_DECLARED, note="connector you listed")
    extension.gap(f"connector {name}", "runs on the provider's side; only its role in chains is considered")
    return extension


def _diff(arguments: argparse.Namespace) -> int:
    old = _load_all([arguments.old])
    new = _load_all([arguments.new])
    if len(old) == 1 and len(new) == 1:
        updates = snapshot.diff(snapshot.build(old[0]), snapshot.build(new[0]))
    else:
        updates = snapshot.diff_sets(snapshot.build_set(old), snapshot.build_set(new))
    return _finish(report.Result(new, updates=updates), arguments, updates_only=True)


def _baseline(arguments: argparse.Namespace) -> int:
    extensions, searched = discover.discover(projects=arguments.project)
    _analyze(extensions)
    _go_online(extensions, arguments)
    current = snapshot.build_set(extensions)
    path = Path(arguments.file)
    if arguments.action == "save":
        path.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
        print(f"Saved a baseline of {len(extensions)} extension(s) to {path}")
        return 0
    try:
        saved = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise loaders.LoadError(f"{path} is not a readable baseline") from exc
    if saved.get("format") != snapshot.FORMAT_VERSION:
        raise loaders.LoadError(f"{path} was saved by an incompatible version")
    updates = snapshot.diff_sets(saved, current)
    return _finish(report.Result(extensions, updates=updates, searched=searched), arguments, updates_only=True)


def _finish(result: report.Result, arguments: argparse.Namespace, updates_only: bool = False) -> int:
    report.prepare(result, set(arguments.ignore))
    if updates_only:
        for extension in result.extensions:
            extension.findings = []
    minimum = Severity[arguments.min_severity.upper()]
    if arguments.format == "json":
        text = report.render_json(result)
    elif arguments.format == "sarif":
        text = report.render_sarif(result)
    else:
        text = report.render_text(result, minimum)
    if arguments.output:
        arguments.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if arguments.fail_on == "none":
        return 0
    threshold = Severity[arguments.fail_on.upper()]
    return 1 if any(f.severity >= threshold for f in result.all_findings()) else 0
