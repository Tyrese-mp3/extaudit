"""Run with: python -m benchmark [--set cases|holdout|holdout2|holdout3] [--misses] [--json FILE]"""

from __future__ import annotations

import argparse
import collections
import importlib
import json
import sys

from extaudit import analyzers, declarations, loaders
from extaudit.model import Extension, PackageFile, Severity


def run_case(case) -> Extension:
    extension = Extension(name="case", kind="source", location="memory")
    extension.files = [PackageFile(path, text.encode("utf-8")) for path, text in case.files.items()]
    extension.kind = loaders._detect_kind(extension)
    declarations.parse(extension)
    return analyzers.analyze(extension)


def caught(case, extension: Extension) -> bool:
    return any(
        finding.severity >= case.minimum and finding.rule.startswith(case.expect)
        for finding in extension.findings
    )


def clean(case, extension: Extension) -> tuple[bool, list[str]]:
    noisy = [
        f"{finding.severity.label} {finding.rule}"
        for finding in extension.findings
        if finding.severity > case.ceiling and not finding.rule.startswith("supply.")
    ]
    return not noisy, noisy


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--set", choices=["cases", "holdout", "holdout2", "holdout3"], default="cases", help="which samples to score")
    parser.add_argument("--misses", action="store_true", help="list every failed case")
    parser.add_argument("--json", help="write per-case results to a file")
    arguments = parser.parse_args()

    module = importlib.import_module(f"benchmark.{arguments.set}")
    passed = collections.Counter()
    total = collections.Counter()
    failures: list[str] = []
    results: dict[str, bool] = {}
    for case in module.ALL:
        extension = run_case(case)
        if case.benign:
            ok, noise = clean(case, extension)
            detail = "; ".join(noise[:3])
        else:
            ok = caught(case, extension)
            found = sorted({f"{f.severity.label} {f.rule}" for f in extension.findings})
            detail = "; ".join(found[:3]) or "nothing"
        total[case.group] += 1
        passed[case.group] += ok
        results[f"{case.group}/{case.name}"] = ok
        if not ok:
            failures.append(f"  {case.group}: {case.name}  -> {detail}")

    attacks = sum(n for g, n in total.items() if not g.startswith("benign"))
    attacks_ok = sum(n for g, n in passed.items() if not g.startswith("benign"))
    benign_total = sum(n for g, n in total.items() if g.startswith("benign"))
    benign_ok = sum(n for g, n in passed.items() if g.startswith("benign"))

    for group in total:
        print(f"  {group:16}{passed[group]:4}/{total[group]}")
    print(f"attacks caught:  {attacks_ok}/{attacks}  ({attacks_ok / max(attacks, 1):.0%})")
    print(f"benign clean:    {benign_ok}/{benign_total}  ({benign_ok / max(benign_total, 1):.0%})")
    if arguments.misses:
        print("failures:")
        print("\n".join(failures) or "  none")
    if arguments.json:
        with open(arguments.json, "w", encoding="utf-8") as handle:
            json.dump(results, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
