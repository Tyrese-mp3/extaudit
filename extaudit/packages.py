"""Work out which published package a launch command would fetch. No network here.

These strings come from config files written by whoever made the extension, and they
end up in registry URLs, so names and versions are checked strictly before use.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

NPM = "npm"
PYPI = "pypi"

NPM_NAME = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")
URL_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
EXACT_NPM = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
PYPI_SPEC = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:(?:==|@)\s*([A-Za-z0-9._+!-]+)|((?:[<>=!~]=?).*))?$"
)
NOT_A_REGISTRY = re.compile(r"^(?:[A-Za-z+]+:|\.|/|\\|~)")

NPM_RUNNERS = {"npx", "pnpx", "bunx"}
PYPI_RUNNERS = {"uvx"}
SUBCOMMANDS = {
    ("pnpm", "dlx"): NPM,
    ("yarn", "dlx"): NPM,
    ("npm", "exec"): NPM,
    ("bun", "x"): NPM,
    ("pipx", "run"): PYPI,
}
PACKAGE_FLAGS = {NPM: {"-p", "--package"}, PYPI: {"--from", "--spec"}}
VALUE_FLAGS = {
    NPM: {"--cache", "--userconfig", "-w", "--workspace", "--node-options", "-c", "--call"},
    PYPI: {"--python", "-p", "--with", "--cache-dir", "--directory", "--constraints", "-c"},
}
REGISTRY_FLAGS = {"--registry", "--index-url", "-i", "--index", "--default-index", "--extra-index-url"}


@dataclass(frozen=True)
class PackageSpec:
    ecosystem: str
    name: str
    requested: str = ""  # a version, tag or range, exactly as written
    exact: bool = False

    def __str__(self) -> str:
        return f"{self.ecosystem}:{self.name}{'@' + self.requested if self.requested else ''}"


def parse_npm(text: str) -> PackageSpec | None:
    """Read name, name@version or @scope/name@version. Paths and URLs are not packages."""
    text = text.strip()
    if NOT_A_REGISTRY.match(text) or ("/" in text and not text.startswith("@")):
        return None
    at = text.find("@", 1)
    name = text[:at] if at > 0 else text
    requested = text[at + 1 :] if at > 0 else ""
    if not NPM_NAME.match(name):
        return None
    return PackageSpec(NPM, name, requested, bool(EXACT_NPM.match(requested)))


def parse_pypi(text: str) -> PackageSpec | None:
    """Read name, name==1.2, name@1.2, name[extra]==1.2 or name>=1.2."""
    text = text.strip()
    if NOT_A_REGISTRY.match(text):
        return None
    match = PYPI_SPEC.match(text)
    if match is None or not PYPI_NAME.match(match.group(1)):
        return None
    exact, loose = match.group(2), match.group(3)
    if exact == "latest":
        exact = None
    return PackageSpec(PYPI, match.group(1), exact or (loose or "").strip(), bool(exact))


def parse_spec(text: str) -> PackageSpec | None:
    """Read a package named on the command line: npm:x, pypi:x, or a bare name for npm."""
    if text.startswith("pypi:"):
        return parse_pypi(text[5:])
    return parse_npm(text.removeprefix("npm:"))


def from_command(command: str, args: list[str]) -> tuple[PackageSpec | None, str]:
    """Return what a launch command fetches, or why it cannot be read from a registry.

    An empty reason means the command is not a package runner at all.
    """
    program = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".cmd", ".exe", ".ps1"):
        program = program.removesuffix(suffix)
    rest = list(args)
    ecosystem = ""
    if program in NPM_RUNNERS:
        ecosystem = NPM
    elif program in PYPI_RUNNERS:
        ecosystem = PYPI
    elif rest and (program, rest[0]) in SUBCOMMANDS:
        ecosystem = SUBCOMMANDS[(program, rest[0])]
        rest = rest[1:]
    elif program == "uv" and rest[:2] == ["tool", "run"]:
        ecosystem = PYPI
        rest = rest[2:]
    if not ecosystem:
        return None, ""
    target, reason = _target(rest, ecosystem)
    if reason:
        return None, reason
    if not target:
        return None, "the launch command names no package"
    spec = parse_npm(target) if ecosystem == NPM else parse_pypi(target)
    if spec is None:
        return None, f"'{target[:80]}' is not a registry package, so it could not be read"
    return spec, ""


def _target(args: list[str], ecosystem: str) -> tuple[str, str]:
    skip = False
    for index, arg in enumerate(args):
        if skip:
            skip = False
            continue
        flag, equals, value = arg.partition("=")
        if flag in REGISTRY_FLAGS:
            return "", "it uses a custom package source, so the public registry copy may not be what runs"
        if flag in PACKAGE_FLAGS[ecosystem]:
            if equals:
                return value, ""
            return (args[index + 1], "") if index + 1 < len(args) else ("", "")
        if arg == "--":
            return (args[index + 1], "") if index + 1 < len(args) else ("", "")
        if arg.startswith("-"):
            skip = not equals and flag in VALUE_FLAGS[ecosystem]
            continue
        return arg, ""
    return "", ""


# A small part of semver: enough to pick the version npm would install for a dependency.

VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
COMPARATOR = re.compile(r"^(>=|<=|>|<|=|\^|~)?v?(\d+|[xX*])?(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?$")
MAX_RANGE = 256

Triple = tuple[int, int, int]


def _version(text: str) -> tuple[Triple, str] | None:
    match = VERSION.match(text)
    return ((int(match[1]), int(match[2]), int(match[3])), match[4] or "") if match else None


def _comparators(token: str) -> list[tuple[str, Triple]] | None:
    match = COMPARATOR.match(token)
    if match is None:
        return None
    operator = match[1] or ""
    numbers = [match[2], match[3], match[4]]
    if numbers[0] is None or numbers[0] in {"x", "X", "*"}:
        return []
    known = [int(n) for n in _takewhile_numeric(numbers)]
    base = (*known, *([0] * (3 - len(known))))
    major, minor, patch = base
    if operator == "^":
        if major:
            upper = (major + 1, 0, 0)
        elif minor or len(known) < 3:
            upper = (0, minor + 1, 0) if len(known) > 1 else (1, 0, 0)
        else:
            upper = (0, 0, patch + 1)
        return [(">=", base), ("<", upper)]
    if operator == "~":
        upper = (major, minor + 1, 0) if len(known) > 1 else (major + 1, 0, 0)
        return [(">=", base), ("<", upper)]
    if operator in {"", "="}:
        if len(known) == 3:
            return [("=", base)]
        upper = (major, minor + 1, 0) if len(known) == 2 else (major + 1, 0, 0)
        return [(">=", base), ("<", upper)]
    return [(operator, base)]


def _takewhile_numeric(numbers: list[str | None]) -> list[str]:
    out = []
    for number in numbers:
        if number is None or not number.isdigit():
            break
        out.append(number)
    return out


def _holds(version: Triple, operator: str, bound: Triple) -> bool:
    return {
        ">=": version >= bound, ">": version > bound, "<=": version <= bound,
        "<": version < bound, "=": version == bound,
    }[operator]


def max_satisfying(versions: list[str], expression: str) -> str | None:
    """Return the highest published version a range allows, as npm would pick it."""
    expression = expression.strip()
    if len(expression) > MAX_RANGE:
        return None
    expression = re.sub(r"(\S+)\s+-\s+(\S+)", r">=\1 <=\2", expression)
    expression = re.sub(r"([<>=~^]+)\s+", r"\1", expression)
    alternatives = []
    for part in expression.split("||"):
        tokens = part.split()
        if any(token in {"latest", "next"} for token in tokens):
            return None
        comparators: list[tuple[str, Triple]] = []
        for token in tokens:
            parsed = _comparators(token)
            if parsed is None:
                return None
            comparators.extend(parsed)
        alternatives.append(comparators)
    best: tuple[Triple, str] | None = None
    best_text = None
    for text in versions:
        parsed_version = _version(text)
        if parsed_version is None or parsed_version[1]:
            continue  # prereleases are never picked by a plain range
        number = parsed_version[0]
        if any(all(_holds(number, op, bound) for op, bound in group) for group in alternatives):
            if best is None or number > best[0]:
                best, best_text = parsed_version, text
    return best_text
