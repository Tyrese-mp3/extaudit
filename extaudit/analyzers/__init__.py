"""Analyzers run in order; later ones read what earlier ones recorded."""

from ..model import Extension
from . import config, documents, javascript, lines, payloads, purpose, python_ast, shell, supply

PIPELINE = [python_ast, javascript, shell, lines, payloads, documents, config, purpose, supply]


def analyze(extension: Extension) -> Extension:
    for analyzer in PIPELINE:
        # Hostile input must not take down the whole report: a file that crashes an
        # analyzer would otherwise hide every other finding in the scan.
        try:
            analyzer.analyze(extension)
        except Exception as exc:
            label = analyzer.__name__.rsplit(".", 1)[-1]
            extension.gap(f"{label} analyzer", f"stopped early ({type(exc).__name__}); results are incomplete")
    return extension
