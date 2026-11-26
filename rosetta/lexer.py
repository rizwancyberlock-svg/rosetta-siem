"""Tokenizer and pattern helpers shared by the parsers."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .ir import Cmp, ConversionError

REGEX_META = set(".^$*+?()[]{}|\\")


@dataclass
class Tok:
    kind: str
    val: str


def tokenize(text: str, spec: list[tuple[str, str]], flags: int = 0) -> list[Tok]:
    rx = re.compile("|".join(f"(?P<{k}>{p})" for k, p in spec), flags)
    pos, out = 0, []
    while pos < len(text):
        m = rx.match(text, pos)
        if not m or m.end() == pos:
            raise ConversionError(f"cannot tokenize near: {text[pos:pos + 40]!r}")
        if m.lastgroup != "WS":
            out.append(Tok(m.lastgroup, m.group(m.lastgroup)))
        pos = m.end()
    return out


class Stream:
    def __init__(self, toks: list[Tok]):
        self.t, self.i = toks, 0

    def peek(self, k: int = 0) -> Tok | None:
        return self.t[self.i + k] if self.i + k < len(self.t) else None

    def next(self) -> Tok:
        tok = self.peek()
        if tok is None:
            raise ConversionError("unexpected end of query")
        self.i += 1
        return tok

    def at(self, kind: str, val: str | None = None, ci: bool = True) -> bool:
        tok = self.peek()
        if tok is None or tok.kind != kind:
            return False
        if val is None:
            return True
        return tok.val.lower() == val.lower() if ci else tok.val == val

    def at_word(self, *words: str) -> bool:
        tok = self.peek()
        return tok is not None and tok.kind in ("IDENT", "WORD") and tok.val.lower() in words

    def expect(self, kind: str, val: str | None = None) -> Tok:
        if not self.at(kind, val):
            got = self.peek()
            raise ConversionError(f"expected {val or kind}, got {got.val if got else 'end of query'!r}")
        return self.next()

    def done(self) -> bool:
        return self.i >= len(self.t)


# --------------------------------------------------------------------------- patterns

def unescape_regex_literal(s: str) -> str | None:
    """Return the literal text if `s` is a regex with no metacharacters, else None."""
    out, i = [], 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            if i + 1 < len(s) and not s[i + 1].isalnum():
                out.append(s[i + 1])
                i += 2
                continue
            return None
        if c in REGEX_META:
            return None
        out.append(c)
        i += 1
    return "".join(out) if out else None


def regex_to_cmp(field: str, pattern: str, nocase: bool) -> Cmp:
    """Simplify literal-only regexes into eq / contains / startswith / endswith."""
    p = pattern
    if p.startswith("(?i)"):
        p, nocase = p[4:], True
    starts = p.startswith("^")
    ends = p.endswith("$") and not p.endswith("\\$")
    core = p[1 if starts else 0: len(p) - 1 if ends else len(p)]
    if core.startswith(".*"):
        core, starts = core[2:], False
    if core.endswith(".*") and not core.endswith("\\.*"):
        core, ends = core[:-2], False
    lit = unescape_regex_literal(core)
    if lit is None:
        return Cmp(field, "regex", p, nocase)
    op = "eq" if starts and ends else "startswith" if starts else "endswith" if ends else "contains"
    return Cmp(field, op, lit, nocase)


def re_escape(s: str) -> str:
    return "".join("\\" + c if c in REGEX_META or c == "/" else c for c in s)


def wildcard_to_cmp(field: str, value: str, wildcard: str, single: str | None, nocase: bool) -> Cmp:
    """Convert SPL `*` or SQL LIKE `%` / `_` patterns into a Cmp."""
    has_single = single is not None and single in value
    if wildcard not in value and not has_single:
        return Cmp(field, "eq", value, nocase)
    inner = value.strip(wildcard)
    if not has_single and inner and wildcard not in inner:
        lead, trail = value.startswith(wildcard), value.endswith(wildcard)
        op = "contains" if lead and trail else "endswith" if lead else "startswith"
        return Cmp(field, op, inner, nocase)
    rx = "".join(".*" if c == wildcard else "." if c == single else re_escape(c) for c in value)
    return Cmp(field, "regex", f"^{rx}$", nocase)


CIDR_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$")
WINDOW_RE = re.compile(r"^(\d+)\s*([smhd])$")


def norm_window(value: str, unit: str | None = None) -> str:
    """'30m' / ('30','MINUTES') -> '30m'"""
    if unit:
        u = unit.lower()[0]
        return f"{int(value)}{'m' if u == 'm' else 'h' if u == 'h' else 'd' if u == 'd' else 's'}"
    m = WINDOW_RE.match(value.strip())
    if not m:
        raise ConversionError(f"unsupported time window {value!r}")
    return f"{m.group(1)}{m.group(2)}"
