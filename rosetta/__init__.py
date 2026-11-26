"""rosetta-siem - translate detection queries between YARA-L, KQL, SPL and AQL."""
from __future__ import annotations

import copy

from .ir import ConversionError, Rule
from .parsers import PARSERS
from .renderers import RENDERERS

__version__ = "0.1.0"
LANGUAGES = ("yaral", "kql", "spl", "aql")
LANGUAGE_NAMES = {
    "yaral": "YARA-L 2.0 (Google SecOps)",
    "kql": "KQL (Microsoft Sentinel, ASIM)",
    "spl": "SPL (Splunk, CIM)",
    "aql": "AQL (IBM QRadar)",
}

__all__ = ["convert", "parse", "render", "ConversionError", "Rule", "LANGUAGES"]


def parse(text: str, source: str) -> Rule:
    if source not in PARSERS:
        raise ValueError(f"unknown source language {source!r}; choose from {LANGUAGES}")
    return PARSERS[source](text)


def render(rule: Rule, target: str) -> str:
    if target not in RENDERERS:
        raise ValueError(f"unknown target language {target!r}; choose from {LANGUAGES}")
    return RENDERERS[target](rule)


def convert(text: str, source: str, target: str) -> tuple[str, list[str]]:
    """Convert `text` from `source` to `target`. Returns (query, warnings)."""
    rule = parse(text, source)
    rule = copy.deepcopy(rule)
    out = render(rule, target)
    return out, rule.warnings
