"""Renderers: IR -> YARA-L 2.0, KQL (Sentinel ASIM), SPL (Splunk CIM), AQL (QRadar)."""
from __future__ import annotations

import re

from . import fields as F
from .ir import And, Cmp, ConversionError, Not, Or, Rule, walk
from .lexer import re_escape

# --------------------------------------------------------------------------- helpers


def _nc(c: Cmp) -> bool:
    """Case-insensitivity only matters when the value contains letters."""
    if not c.nocase:
        return False
    vals = c.value if isinstance(c.value, list) else [c.value]
    return any(isinstance(v, str) and any(ch.isalpha() for ch in v) for v in vals)


class _Ctx:
    def __init__(self, rule: Rule, lang: str):
        self.rule, self.lang = rule, lang
        self.native_lang = "udm" if lang == "yaral" else lang

    def field(self, canonical: str) -> str:
        if ":" in canonical:
            src, name = canonical.split(":", 1)
            if src in F.LANGS and src != self.native_lang:
                self.rule.warn(f"field '{name}' from {src} has no mapping to {self.lang}; kept verbatim - map it manually")
            return name
        native = F.to_native(self.native_lang, canonical, self.rule.category)
        if native is None:
            raise ConversionError(f"{self.lang} has no field for '{canonical}'")
        return native

    def value(self, cmp: Cmp):
        v = cmp.value
        if cmp.field == "event.outcome":
            m = F.OUTCOME_VALUES[self.native_lang]
            if isinstance(v, list):
                return [m.get(x, x) for x in v]
            return m.get(v, v)
        if cmp.field in F.NUMERIC and isinstance(v, str) and v.isdigit():
            return int(v)
        if isinstance(v, list) and cmp.field in F.NUMERIC:
            return [int(x) if isinstance(x, str) and x.isdigit() else x for x in v]
        return v


def _name_to_path(cmp: Cmp, ctx: _Ctx) -> Cmp:
    """process.name -> process.path endswith, for schemas without a name field."""
    if cmp.field in ("process.name", "process.parent.name") and F.to_native(ctx.native_lang, cmp.field) is None:
        path_field = cmp.field.replace(".name", ".path")
        ctx.rule.warn(f"'{cmp.field}' converted to an ends-with match on '{path_field}'")
        if cmp.op == "eq":
            return Cmp(path_field, "endswith", cmp.value, cmp.nocase)
        if cmp.op == "in":
            return Or([Cmp(path_field, "endswith", v, cmp.nocase) for v in cmp.value])
        if cmp.op == "ne":
            return Not(Cmp(path_field, "endswith", cmp.value, cmp.nocase))
        return Cmp(path_field, cmp.op, cmp.value, cmp.nocase)
    return cmp


def _expr(e, ctx: _Ctx, cmp_fn, and_sep: str, or_sep: str, not_fmt: str, top: bool = False) -> str:
    if isinstance(e, Cmp):
        e2 = _name_to_path(e, ctx)
        if isinstance(e2, Cmp) and e2.nocase and not _nc(e2):
            e2 = Cmp(e2.field, e2.op, e2.value, False)
        if not isinstance(e2, Cmp):
            return _expr(e2, ctx, cmp_fn, and_sep, or_sep, not_fmt)
        return cmp_fn(e2, ctx)
    if isinstance(e, Not):
        return not_fmt.format(_expr(e.item, ctx, cmp_fn, and_sep, or_sep, not_fmt))
    sep = and_sep if isinstance(e, And) else or_sep
    inner = sep.join(_expr(i, ctx, cmp_fn, and_sep, or_sep, not_fmt) for i in e.items)
    return inner if top and isinstance(e, And) else f"({inner})"


def _safe_name(name: str) -> str:
    n = re.sub(r"\W+", "_", name).strip("_").lower()
    return n if n and n[0].isalpha() else f"rule_{n}"


# =========================================================================== YARA-L

def _yq(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _yaral_cmp(c: Cmp, ctx: _Ctx) -> str:
    f = "$e." + ctx.field(c.field)
    v = ctx.value(c)
    nc = " nocase" if c.nocase else ""
    if c.op in ("eq", "ne"):
        sym = "=" if c.op == "eq" else "!="
        if isinstance(v, bool):
            return f"{f} {sym} {'true' if v else 'false'}"
        if isinstance(v, (int, float)):
            return f"{f} {sym} {v}"
        return f"{f} {sym} {_yq(v)}{nc}"
    if c.op in ("contains", "startswith", "endswith"):
        pre = "^" if c.op == "startswith" else ""
        suf = "$" if c.op == "endswith" else ""
        return f"{f} = /{pre}{re_escape(str(v))}{suf}/{nc}"
    if c.op == "regex":
        return f"{f} = /{re.sub(r'(?<!\\)/', r'\\/', v)}/{nc}"
    if c.op == "in":
        parts = [f"{f} = {v_ if isinstance(v_, (int, float)) else _yq(str(v_)) + nc}" for v_ in v]
        return "(" + " or ".join(parts) + ")"
    if c.op in ("gt", "ge", "lt", "le"):
        return f"{f} {dict(gt='>', ge='>=', lt='<', le='<=')[c.op]} {v}"
    if c.op == "cidr":
        return f'net.ip_in_range_cidr({f}, "{v}")'
    raise ConversionError(f"operator {c.op} not supported in YARA-L")


def render_yaral(rule: Rule) -> str:
    ctx = _Ctx(rule, "yaral")
    lines = []
    if rule.category in F.CATEGORY_UDM:
        lines.append(f'$e.metadata.event_type = "{F.CATEGORY_UDM[rule.category]}"')
    cond = rule.condition
    items = cond.items if isinstance(cond, And) else ([cond] if cond is not None else [])
    for it in items:
        lines.append(_expr(it, ctx, _yaral_cmp, " and ", " or ", "not {}", top=True))
    match = condition = None
    outcome = []
    agg = rule.aggregation
    if agg:
        phs = []
        for g in agg.group_by:
            ph = "$" + re.sub(r"\W", "_", ctx.field(g).split(".")[-1])
            lines.append(f"$e.{ctx.field(g)} = {ph}")
            phs.append(ph)
        if not phs:
            lines.append("$e.metadata.vendor_name = $vendor")
            phs.append("$vendor")
            rule.warn("YARA-L needs a match variable; grouped by metadata.vendor_name")
        window = agg.window or "1h"
        if not agg.window:
            rule.warn("no time window in source; defaulted YARA-L match window to 1h")
        match = f"{', '.join(phs)} over {window}"
        if agg.distinct_field:
            lines.append(f"$e.{ctx.field(agg.distinct_field)} = $distinct_value")
            condition = f"#distinct_value {agg.op if agg.op != '=' else '=='} {agg.threshold}"
        else:
            condition = f"#e {agg.op if agg.op != '=' else '=='} {agg.threshold}"
        outcome.append("$event_count = count($e.metadata.id)")
    if not lines:
        raise ConversionError("nothing to convert - the query has no filter conditions")
    meta = [f'author = "rosetta-siem"', f"description = {_yq(rule.description or 'Converted by rosetta-siem')}"]
    if rule.severity:
        meta.append(f'severity = "{rule.severity}"')
    if rule.tactics:
        meta.append(f'mitre_attack_tactic = "{", ".join(rule.tactics)}"')
    if rule.techniques:
        meta.append(f'mitre_attack_technique = "{", ".join(rule.techniques)}"')
    out = [f"rule {_safe_name(rule.name)} {{", "  meta:"] + ["    " + m for m in meta]
    out += ["", "  events:"] + ["    " + ln for ln in lines]
    if match:
        out += ["", "  match:", "    " + match]
    if outcome:
        out += ["", "  outcome:"] + ["    " + o for o in outcome]
    out += ["", "  condition:", "    " + (condition or "$e"), "}"]
    return "\n".join(out) + "\n"


# =========================================================================== KQL

def _kq(v: str) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _kql_cmp(c: Cmp, ctx: _Ctx) -> str:
    f = ctx.field(c.field)
    v = ctx.value(c)
    if c.op in ("eq", "ne"):
        if isinstance(v, bool):
            return f"{f} {'==' if c.op == 'eq' else '!='} {'true' if v else 'false'}"
        if isinstance(v, (int, float)):
            return f"{f} {'==' if c.op == 'eq' else '!='} {v}"
        if v == "":
            return f"isnotempty({f})" if c.op == "ne" else f"isempty({f})"
        sym = {"eq": ("==", "=~"), "ne": ("!=", "!~")}[c.op][c.nocase]
        return f"{f} {sym} {_kq(v)}"
    if c.op in ("contains", "startswith", "endswith"):
        cs = not c.nocase and any(ch.isalpha() for ch in str(v))
        return f"{f} {c.op}{'_cs' if cs else ''} {_kq(v)}"
    if c.op == "regex":
        return f"{f} matches regex {_kq(('(?i)' if c.nocase else '') + v)}"
    if c.op == "in":
        vals = ", ".join(str(x) if isinstance(x, (int, float)) else _kq(x) for x in v)
        return f"{f} {'in~' if c.nocase else 'in'} ({vals})"
    if c.op in ("gt", "ge", "lt", "le"):
        return f"{f} {dict(gt='>', ge='>=', lt='<', le='<=')[c.op]} {v}"
    if c.op == "cidr":
        return f'ipv4_is_in_range({f}, "{v}")'
    raise ConversionError(f"operator {c.op} not supported in KQL")


def render_kql(rule: Rule) -> str:
    ctx = _Ctx(rule, "kql")
    if rule.category in F.CATEGORY_ASIM:
        table = F.CATEGORY_ASIM[rule.category]
    elif rule.source_hint.get("kql_table"):
        table = rule.source_hint["kql_table"]
    else:
        table = "union *"
        rule.warn("no event category; query runs over all tables (union *) - set the right table")
    out = [table]
    cond = rule.condition
    if cond is not None:
        items = cond.items if isinstance(cond, And) else [cond]
        rendered = [_expr(i, ctx, _kql_cmp, " and ", " or ", "not({})", top=True) for i in items]
        out.append("| where " + "\n    and ".join(rendered))
    agg = rule.aggregation
    if agg:
        aggs = ["EventCount = count()"]
        if agg.distinct_field:
            aggs.append(f"DistinctCount = dcount({ctx.field(agg.distinct_field)})")
        by = [ctx.field(g) for g in agg.group_by]
        if agg.window:
            by.append(f"bin(TimeGenerated, {agg.window})")
        out.append(f"| summarize {', '.join(aggs)}" + (f" by {', '.join(by)}" if by else ""))
        metric = "DistinctCount" if agg.distinct_field else "EventCount"
        op = "==" if agg.op == "=" else agg.op
        out.append(f"| where {metric} {op} {agg.threshold}")
    return "\n".join(out) + "\n"


# =========================================================================== SPL

def _sq(v) -> str:
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spl_search_cmp(c: Cmp, ctx: _Ctx) -> str:
    f = ctx.field(c.field)
    v = ctx.value(c)
    if isinstance(v, str) and "*" in v:
        ctx.rule.warn("value contains '*', which Splunk search treats as a wildcard")
    if c.op == "eq":
        return f"{f}={v}" if isinstance(v, (int, float)) else f"{f}={_sq(v)}"
    if c.op == "ne":
        return f"{f}!={v}" if isinstance(v, (int, float)) else f"{f}!={_sq(v)}"
    if c.op == "contains":
        return f'{f}={_sq("*" + v + "*")}'
    if c.op == "startswith":
        return f'{f}={_sq(v + "*")}'
    if c.op == "endswith":
        return f'{f}={_sq("*" + v)}'
    if c.op == "in":
        return f"{f} IN ({', '.join(str(x) if isinstance(x, (int, float)) else _sq(x) for x in v)})"
    if c.op in ("gt", "ge", "lt", "le"):
        return f"{f}{dict(gt='>', ge='>=', lt='<', le='<=')[c.op]}{v}"
    if c.op == "cidr":
        return f"{f}={v}"
    raise ConversionError(f"operator {c.op} needs eval syntax")


def _ef(name: str) -> str:
    return name if re.fullmatch(r"[A-Za-z_]\w*", name) else f"'{name}'"


def _spl_eval_cmp(c: Cmp, ctx: _Ctx) -> str:
    f = _ef(ctx.field(c.field))
    v = ctx.value(c)
    lf = f"lower({f})" if c.nocase else f
    lv = (lambda x: str(x).lower()) if c.nocase else (lambda x: str(x))
    if c.op in ("eq", "ne"):
        sym = "==" if c.op == "eq" else "!="
        return f"{f}{sym}{v}" if isinstance(v, (int, float)) else f"{lf}{sym}{_sq(lv(v))}"
    if c.op in ("contains", "startswith", "endswith"):
        pat = {"contains": "%{}%", "startswith": "{}%", "endswith": "%{}"}[c.op].format(lv(v))
        return f"like({lf}, {_sq(pat)})"
    if c.op == "regex":
        return f"match({f}, {_sq(('(?i)' if c.nocase else '') + v)})"
    if c.op == "in":
        return f"in({lf}, {', '.join(_sq(lv(x)) for x in v)})"
    if c.op in ("gt", "ge", "lt", "le"):
        return f"{f}{dict(gt='>', ge='>=', lt='<', le='<=')[c.op]}{v}"
    if c.op == "cidr":
        return f'cidrmatch("{v}", {f})'
    raise ConversionError(f"operator {c.op} not supported in SPL")


def _needs_eval(e) -> bool:
    return any(c.op == "regex" for c in walk(e))


def render_spl(rule: Rule) -> str:
    ctx = _Ctx(rule, "spl")
    prefix = " ".join(rule.source_hint.get("spl", [])) or "index=*"
    if rule.category in F.CATEGORY_SPL_TAGS:
        prefix += " " + F.CATEGORY_SPL_TAGS[rule.category]
    cond = rule.condition
    items = cond.items if isinstance(cond, And) else ([cond] if cond is not None else [])
    search = [i for i in items if not _needs_eval(i)]
    where = [i for i in items if _needs_eval(i)]
    s_txt = [_expr(i, ctx, _spl_search_cmp, " ", " OR ", "NOT {}", top=True) for i in search]
    out = [" ".join([prefix] + s_txt)]
    if where:
        out.append("| where " + " AND ".join(_expr(i, ctx, _spl_eval_cmp, " AND ", " OR ", "NOT ({})", top=True)
                                              for i in where))
    agg = rule.aggregation
    if agg:
        by = [ctx.field(g) for g in agg.group_by]
        stats = "count AS event_count"
        if agg.distinct_field:
            stats += f" dc({ctx.field(agg.distinct_field)}) AS distinct_count"
        if agg.window:
            out.append(f"| bin _time span={agg.window}")
            by = ["_time"] + by
        out.append(f"| stats {stats}" + (f" BY {' '.join(by)}" if by else ""))
        metric = "distinct_count" if agg.distinct_field else "event_count"
        out.append(f"| where {metric}{'==' if agg.op == '=' else agg.op}{agg.threshold}")
    return "\n".join(out) + "\n"


# =========================================================================== AQL

def _aq(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def _af(name: str) -> str:
    if "(" in name or re.fullmatch(r"[a-z_][a-z0-9_]*", name):
        return name
    return f'"{name}"'


def _aql_cmp(c: Cmp, ctx: _Ctx) -> str:
    f = _af(ctx.field(c.field))
    v = ctx.value(c)
    like = "ILIKE" if c.nocase else "LIKE"
    if c.op in ("eq", "ne"):
        if isinstance(v, (int, float, bool)):
            return f"{f} {'=' if c.op == 'eq' else '!='} {v}"
        if v == "":
            return f"{f} IS {'NOT ' if c.op == 'ne' else ''}NULL"
        if c.nocase:
            expr = f"{f} ILIKE {_aq(v)}"
            return expr if c.op == "eq" else f"NOT {expr}"
        return f"{f} {'=' if c.op == 'eq' else '!='} {_aq(v)}"
    if c.op in ("contains", "startswith", "endswith"):
        pat = {"contains": "%{}%", "startswith": "{}%", "endswith": "%{}"}[c.op].format(v)
        return f"{f} {like} {_aq(pat)}"
    if c.op == "regex":
        return f"{f} {'IMATCHES' if c.nocase else 'MATCHES'} {_aq(v)}"
    if c.op == "in":
        return f"{f} IN ({', '.join(str(x) if isinstance(x, (int, float)) else _aq(x) for x in v)})"
    if c.op in ("gt", "ge", "lt", "le"):
        return f"{f} {dict(gt='>', ge='>=', lt='<', le='<=')[c.op]} {v}"
    if c.op == "cidr":
        return f"INCIDR({_aq(v)}, {f})"
    raise ConversionError(f"operator {c.op} not supported in AQL")


def _aql_window(w: str | None) -> str:
    if not w:
        return "LAST 24 HOURS"
    n, u = int(w[:-1]), w[-1]
    return f"LAST {n} " + {"s": "SECONDS", "m": "MINUTES", "h": "HOURS", "d": "DAYS"}[u]


def render_aql(rule: Rule) -> str:
    ctx = _Ctx(rule, "aql")
    if rule.category != "generic":
        rule.warn(f"AQL has no event-category filter for '{rule.category}'; add a log source type filter")
    where = ""
    if rule.condition is not None:
        where = "WHERE " + _expr(rule.condition, ctx, _aql_cmp, " AND ", " OR ", "NOT {}", top=True)
    agg = rule.aggregation
    if agg:
        groups = [_af(ctx.field(g)) for g in agg.group_by]
        metric = f"UNIQUECOUNT({_af(ctx.field(agg.distinct_field))})" if agg.distinct_field else "COUNT(*)"
        cols = groups + [f"{metric} AS {'distinct_count' if agg.distinct_field else 'event_count'}"]
        parts = [f"SELECT {', '.join(cols)} FROM events", where]
        if groups:
            parts.append(f"GROUP BY {', '.join(groups)}")
        parts.append(f"HAVING {metric} {agg.op} {agg.threshold}")
        parts.append(_aql_window(agg.window))
        if agg.window:
            rule.warn("AQL LAST window is a single look-back, not a sliding window like YARA-L/KQL/SPL bins")
    else:
        parts = ["SELECT * FROM events", where, _aql_window(None)]
    return "\n".join(p for p in parts if p) + "\n"


RENDERERS = {"yaral": render_yaral, "kql": render_kql, "spl": render_spl, "aql": render_aql}
