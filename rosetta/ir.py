"""Intermediate representation shared by every parser and renderer.

A query in any language is parsed into a `Rule`:

    Rule.condition    boolean tree of And / Or / Not / Cmp
    Rule.aggregation  optional "count (distinct) ... by fields over window >= N"
    Rule.category     coarse event category (process, authentication, network ...)

Field names inside `Cmp` are *canonical* (ECS-style, e.g. ``process.command_line``)
after parsing. Fields that have no known mapping are kept as ``"<lang>:<name>"``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Union


class ConversionError(Exception):
    """Raised when a query uses constructs that cannot be converted faithfully."""


@dataclass
class Cmp:
    field: str
    op: str  # eq ne contains startswith endswith regex in gt ge lt le cidr
    value: Any = None
    nocase: bool = True


@dataclass
class And:
    items: list


@dataclass
class Or:
    items: list


@dataclass
class Not:
    item: Any


Expr = Union[Cmp, And, Or, Not]

OPS = {"eq", "ne", "contains", "startswith", "endswith", "regex", "in", "gt", "ge", "lt", "le", "cidr"}
CATEGORIES = ("generic", "process", "authentication", "network", "dns", "http", "file", "registry")


@dataclass
class Aggregation:
    group_by: list = field(default_factory=list)
    window: str | None = None          # "30m", "1h", "1d"
    distinct_field: str | None = None  # None = count events
    op: str = ">="
    threshold: int = 1


@dataclass
class Rule:
    name: str = "converted_rule"
    description: str = ""
    severity: str = ""
    tactics: list = field(default_factory=list)
    techniques: list = field(default_factory=list)
    category: str = "generic"
    condition: Expr | None = None
    aggregation: Aggregation | None = None
    source_hint: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

    def warn(self, msg: str) -> None:
        if msg not in self.warnings:
            self.warnings.append(msg)


def and_(items: list) -> Expr | None:
    flat: list = []
    for it in items:
        if it is None:
            continue
        flat.extend(it.items if isinstance(it, And) else [it])
    if not flat:
        return None
    return flat[0] if len(flat) == 1 else And(flat)


def or_(items: list) -> Expr | None:
    flat: list = []
    for it in items:
        if it is None:
            continue
        flat.extend(it.items if isinstance(it, Or) else [it])
    if not flat:
        return None
    return flat[0] if len(flat) == 1 else Or(flat)


def walk(expr: Expr | None):
    """Yield every Cmp in an expression tree."""
    if expr is None:
        return
    if isinstance(expr, Cmp):
        yield expr
    elif isinstance(expr, Not):
        yield from walk(expr.item)
    else:
        for it in expr.items:
            yield from walk(it)
