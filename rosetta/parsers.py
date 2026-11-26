"""Parsers: YARA-L 2.0 (Google SecOps), KQL (Sentinel), SPL (Splunk), AQL (QRadar) -> IR."""
from __future__ import annotations

import re

from . import fields as F
from .ir import Aggregation, Cmp, ConversionError, Not, Rule, and_, or_, walk
from .lexer import (CIDR_RE, Stream, Tok, norm_window, regex_to_cmp, tokenize, wildcard_to_cmp)

CMP_OPS = {"=": "eq", "==": "eq", "!=": "ne", "<>": "ne", ">": "gt", ">=": "ge", "<": "lt", "<=": "le"}

# Windows Security / Sysmon event IDs that pin down the event category.
EVENT_CODE_CATEGORY = {
    "process": {"4688", "1"},
    "authentication": {"4624", "4625", "4648", "4771", "4776", "4768", "4769"},
    "network": {"3", "5156", "5157"},
    "dns": {"22"},
    "file": {"11", "23", "26", "4663"},
    "registry": {"12", "13", "14", "4657"},
}


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", r"\1", s)


def _num(v: str):
    try:
        return int(v)
    except ValueError:
        return float(v)


# =========================================================================== post-processing

def _finalize(rule: Rule, lang: str) -> Rule:
    """Map native field names to canonical ones and normalise outcome values."""
    native_lang = "udm" if lang == "yaral" else lang

    def fix(e):
        if e is None:
            return None
        if isinstance(e, Cmp):
            if not e.field.startswith("@"):
                return e
            e.field = F.to_canonical(native_lang, e.field[1:], rule.category)
            if e.field.startswith(f"{native_lang}:"):
                rule.warn(f"field '{e.field.split(':', 1)[1]}' has no canonical mapping; kept verbatim")
            if e.field in F.NUMERIC and isinstance(e.value, str) and e.value.isdigit():
                e.value = int(e.value)
            if e.nocase and not any(isinstance(v, str) and any(ch.isalpha() for ch in v)
                                    for v in (e.value if isinstance(e.value, list) else [e.value])):
                e.nocase = False
            if e.field == "event.outcome":
                if isinstance(e.value, str):
                    e.value = F.OUTCOME_PARSE.get(e.value.lower(), e.value)
                elif isinstance(e.value, list):
                    e.value = [F.OUTCOME_PARSE.get(str(v).lower(), v) for v in e.value]
            return e
        if isinstance(e, Not):
            e.item = fix(e.item)
            return e
        e.items = [fix(i) for i in e.items]
        return e

    # Infer the category from well-known event IDs *before* mapping fields,
    # because some native names (e.g. Splunk `user`) depend on the category.
    if rule.category == "generic":
        codes = set()
        for c in walk(rule.condition):
            if c.field.startswith("@") and F.to_canonical(native_lang, c.field[1:]) == "event.code":
                if c.op == "eq":
                    codes.add(str(c.value))
                elif c.op == "in":
                    codes.update(str(v) for v in c.value)
        for cat, ids in EVENT_CODE_CATEGORY.items():
            if codes and codes <= ids:
                rule.category = cat
                break
    rule.condition = fix(rule.condition)
    if rule.aggregation:
        agg = rule.aggregation
        agg.group_by = [F.to_canonical(native_lang, g[1:], rule.category) if g.startswith("@") else g
                        for g in agg.group_by]
        if agg.distinct_field and agg.distinct_field.startswith("@"):
            agg.distinct_field = F.to_canonical(native_lang, agg.distinct_field[1:], rule.category)
    return rule


# =========================================================================== YARA-L

YARAL_SPEC = [
    ("WS", r"\s+"),
    ("REGEX", r"/(?:\\.|[^/\\\n])+/"),
    ("STRING", r'"(?:\\.|[^"\\])*"'),
    ("BTSTRING", r"`[^`]*`"),
    ("NUMBER", r"-?\d+(?:\.\d+)?(?![\w.])"),
    ("OP", r"!=|<=|>=|=|<|>"),
    ("LP", r"\("), ("RP", r"\)"), ("COMMA", r","),
    ("IDENT", r"[$%#]?[A-Za-z_][\w.]*(?:\[\"[^\"]*\"\])?"),
]


class _YaralParser:
    def __init__(self, toks: list[Tok], rule: Rule):
        self.s, self.rule = Stream(toks), rule
        self.placeholders: dict[str, str] = {}
        self.event_vars: set[str] = set()
        self.event_types: list[str] = []

    def statements(self, until_rp: bool = False):
        items = []
        while not self.s.done() and not (until_rp and self.s.at("RP")):
            items.append(self.or_expr())
        return and_(items)

    def or_expr(self):
        parts = [self.and_expr()]
        while self.s.at_word("or"):
            self.s.next()
            parts.append(self.and_expr())
        if any(p is None for p in parts) and any(p is not None for p in parts):
            self.rule.warn("an OR branch could not be converted and was dropped - review the logic")
        return or_(parts)

    def and_expr(self):
        parts = [self.unary()]
        while self.s.at_word("and"):
            self.s.next()
            parts.append(self.unary())
        return and_(parts)

    def unary(self):
        if self.s.at_word("not"):
            self.s.next()
            inner = self.unary()
            return Not(inner) if inner is not None else None
        if self.s.at("LP"):
            self.s.next()
            inner = self.statements(until_rp=True)
            self.s.expect("RP")
            return inner
        tok = self.s.peek()
        if tok and tok.kind == "IDENT" and self.s.peek(1) and self.s.peek(1).kind == "LP":
            return self.function()
        return self.comparison()

    def _field(self, ident: str) -> str | None:
        if ident.startswith("$") and "." in ident:
            var, path = ident[1:].split(".", 1)
            self.event_vars.add(var)
            return path
        if ident in self.placeholders:  # $user bound earlier via $e.field = $user
            return self.placeholders[ident]
        return None

    def _require_field(self, ident: str) -> str:
        path = self._field(ident)
        if path is None:
            raise ConversionError(f"{ident} is not bound to a field before it is used")
        return path

    def function(self):
        name = self.s.next().val
        self.s.expect("LP")
        args, depth = [], 0
        while not (self.s.at("RP") and depth == 0):
            tok = self.s.next()
            depth += tok.kind == "LP"
            depth -= tok.kind == "RP"
            if tok.kind != "COMMA" or depth:
                args.append(tok)
        self.s.expect("RP")
        if name == "re.regex" and len(args) == 2:
            path = self._require_field(args[0].val)
            pat = args[1].val[1:-1]
            return regex_to_cmp("@" + path, pat if args[1].kind == "BTSTRING" else _unescape(pat), False)
        if name == "net.ip_in_range_cidr" and len(args) == 2:
            return Cmp("@" + self._require_field(args[0].val), "cidr", args[1].val[1:-1], False)
        if self.s.at("OP"):  # e.g. timestamp.get_hour(...) < 6
            self.s.next()
            self.s.next()
        self.rule.warn(f"function {name}() is not portable and that condition was dropped - add it manually")
        return None

    def comparison(self):
        left = self.s.expect("IDENT").val
        if self.s.at_word("in"):
            self.s.next()
            while self.s.at("IDENT") and not self.s.peek().val.startswith("$"):
                lst = self.s.next().val
                if lst.startswith("%"):
                    self.rule.warn(f"reference list {lst} is not portable and was dropped")
                    break
            return None
        op = self.s.expect("OP").val
        val = self.s.next()
        nocase = False
        if self.s.at_word("nocase"):
            self.s.next()
            nocase = True
        path = self._field(left)
        if path is None:
            if left.startswith("$") and val.kind == "IDENT" and "." in val.val:  # $ph = $e.field
                self.placeholders[left] = self._field(val.val)
                return None
            self.rule.warn(f"unsupported comparison on {left!r} dropped")
            return None
        if val.kind == "IDENT":
            if val.val.startswith("$") and "." not in val.val:
                self.placeholders[val.val] = path
                return None
            if val.val in ("true", "false"):
                return Cmp("@" + path, CMP_OPS[op], val.val == "true", False)
            self.rule.warn(f"field-to-field comparison {left} {op} {val.val} is not supported and was dropped")
            return None
        if path == "metadata.event_type" and op == "=" and val.kind == "STRING":
            self.event_types.append(val.val[1:-1])
            return None
        if val.kind == "REGEX":
            cmp = regex_to_cmp("@" + path, val.val[1:-1].replace("\\/", "/"), nocase)
            return Not(cmp) if op == "!=" else cmp
        if val.kind in ("STRING", "BTSTRING"):
            return Cmp("@" + path, CMP_OPS[op], _unescape(val.val[1:-1]), nocase)
        if val.kind == "NUMBER":
            return Cmp("@" + path, CMP_OPS[op], _num(val.val), False)
        raise ConversionError(f"unexpected value {val.val!r}")


def parse_yaral(text: str) -> Rule:
    rule = Rule()
    m = re.search(r"\brule\s+(\w+)\s*\{", text)
    if not m:
        raise ConversionError("no 'rule <name> {' declaration found")
    rule.name = m.group(1)
    body = text[m.end(): text.rstrip().rfind("}")]
    secs = list(re.finditer(r"^\s*(meta|events|match|outcome|condition|options)\s*:", body, re.M))
    section = {}
    for i, s in enumerate(secs):
        section[s.group(1)] = body[s.end(): secs[i + 1].start() if i + 1 < len(secs) else len(body)]
    for k, v in re.findall(r'(\w+)\s*=\s*"((?:\\.|[^"\\])*)"', section.get("meta", "")):
        v = _unescape(v)
        if k == "description":
            rule.description = v
        elif k == "severity":
            rule.severity = v.upper()
        elif k == "mitre_attack_tactic":
            rule.tactics = [x.strip() for x in v.split(",") if x.strip()]
        elif k == "mitre_attack_technique":
            rule.techniques = [x.strip() for x in v.split(",") if x.strip() and x.strip() != "Multiple"]

    events = re.sub(r"(^|\s)//[^\n]*", r"\1", section.get("events", ""))
    p = _YaralParser(tokenize(events, YARAL_SPEC), rule)
    rule.condition = p.statements()
    if len(p.event_vars) > 1:
        raise ConversionError(f"multi-event rules ({', '.join('$' + v for v in sorted(p.event_vars))}) "
                              "cannot be expressed as a single query - convert each event variable separately")
    if p.event_types:
        cats = {F.UDM_CATEGORY.get(t, "generic") for t in p.event_types}
        rule.category = sorted(cats)[0]
        if len(cats) > 1:
            rule.warn(f"multiple event types {p.event_types}; using category '{rule.category}'")

    match_txt = section.get("match", "").strip()
    cond_txt = re.sub(r"\s+", " ", section.get("condition", "")).strip()
    if match_txt:
        mm = re.match(r"(.+?)\s+over\s+(\d+[smhd])", match_txt, re.S)
        if not mm:
            raise ConversionError(f"unsupported match section: {match_txt!r}")
        agg = Aggregation(window=norm_window(mm.group(2)))
        for ph in [x.strip() for x in mm.group(1).split(",")]:
            if ph not in p.placeholders:
                raise ConversionError(f"match variable {ph} is not bound to a field")
            agg.group_by.append("@" + p.placeholders[ph])
        cm = re.search(r"#(\w+)\s*(>=|>|==|=|<=|<)\s*(\d+)", cond_txt)
        if cm:
            agg.op, agg.threshold = ("=" if cm.group(2) == "==" else cm.group(2)), int(cm.group(3))
            if cm.group(1) not in p.event_vars:
                ph = "$" + cm.group(1)
                if ph not in p.placeholders:
                    raise ConversionError(f"condition references unknown placeholder {ph}")
                agg.distinct_field = "@" + p.placeholders[ph]
        if re.search(r"\$\w+\s*(>|<|=)", cond_txt):
            rule.warn("condition uses outcome variables (e.g. sums); only the event/distinct count was converted")
        rule.aggregation = agg
    return _finalize(rule, "yaral")


# =========================================================================== KQL

KQL_SPEC = [
    ("WS", r"\s+|//[^\n]*"),
    ("STRING", r'@"(?:[^"]|"")*"|@\'(?:[^\']|\'\')*\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    ("KOP", r"!?(?:contains_cs|contains|has_cs|has_any|has|startswith_cs|startswith|endswith_cs|endswith|in~|in)(?![\w~])"),
    ("NUMBER", r"\d+(?:\.\d+)?(?:[smhd](?!\w))?"),
    ("OP", r"==|!=|=~|!~|<=|>=|<|>|="),
    ("LP", r"\("), ("RP", r"\)"), ("LB", r"\["), ("RB", r"\]"), ("COMMA", r","), ("PIPE", r"\|"),
    ("IDENT", r"[A-Za-z_][\w.]*"),
]


def _kql_str(tok: Tok) -> str:
    v = tok.val
    if v.startswith("@"):
        q = v[1]
        return v[2:-1].replace(q + q, q)
    return _unescape(v[1:-1])


class _KqlExpr:
    def __init__(self, toks: list[Tok], rule: Rule):
        self.s, self.rule = Stream(toks), rule

    def parse(self):
        e = self.or_expr()
        if not self.s.done():
            raise ConversionError(f"unexpected token {self.s.peek().val!r} in where clause")
        return e

    def or_expr(self):
        parts = [self.and_expr()]
        while self.s.at_word("or"):
            self.s.next()
            parts.append(self.and_expr())
        return or_(parts)

    def and_expr(self):
        parts = [self.unary()]
        while self.s.at_word("and"):
            self.s.next()
            parts.append(self.unary())
        return and_(parts)

    def values(self):
        if self.s.at_word("dynamic"):
            self.s.next()
            self.s.expect("LP")
            self.s.expect("LB")
            close = ["RB", "RP"]
        else:
            self.s.expect("LP")
            close = ["RP"]
        vals = []
        while not self.s.at(close[0]):
            tok = self.s.next()
            if tok.kind == "STRING":
                vals.append(_kql_str(tok))
            elif tok.kind == "NUMBER":
                vals.append(_num(tok.val))
        for c in close:
            self.s.expect(c)
        return vals

    def unary(self):
        if self.s.at_word("not") and self.s.peek(1) and self.s.peek(1).kind == "LP":
            self.s.next()
            self.s.next()
            inner = self.or_expr()
            self.s.expect("RP")
            return Not(inner)
        if self.s.at("LP"):
            self.s.next()
            inner = self.or_expr()
            self.s.expect("RP")
            return inner
        name = self.s.expect("IDENT").val
        if self.s.at("LP"):
            return self.function(name)
        return self.comparison("@" + name, nocase_hint=False)

    def function(self, name: str):
        self.s.expect("LP")
        low = name.lower()
        if low in ("isnotempty", "isnotnull", "isempty", "isnull"):
            fld = self.s.expect("IDENT").val
            self.s.expect("RP")
            return Cmp("@" + fld, "ne" if "not" in low else "eq", "", False)
        if low == "ipv4_is_in_range":
            fld = self.s.expect("IDENT").val
            self.s.expect("COMMA")
            cidr = _kql_str(self.s.expect("STRING"))
            self.s.expect("RP")
            return Cmp("@" + fld, "cidr", cidr, False)
        if low in ("tolower", "toupper"):
            fld = self.s.expect("IDENT").val
            self.s.expect("RP")
            return self.comparison("@" + fld, nocase_hint=True)
        raise ConversionError(f"KQL function {name}() is not supported")

    def comparison(self, fld: str, nocase_hint: bool):
        tok = self.s.next()
        neg = False
        if tok.kind == "IDENT" and tok.val.lower() == "matches":
            self.s.expect("IDENT", "regex")
            pat = _kql_str(self.s.expect("STRING"))
            return regex_to_cmp(fld, pat, nocase_hint)
        if tok.kind == "KOP":
            op = tok.val
            if op.startswith("!"):
                neg, op = True, op[1:]
            if op in ("in", "in~"):
                cmp = Cmp(fld, "in", self.values(), op == "in~" or nocase_hint)
            elif op == "has_any":
                vals = self.values()
                cmp = or_([Cmp(fld, "contains", v, True) for v in vals])
            else:
                val = self.s.next()
                value = _kql_str(val) if val.kind == "STRING" else val.val
                base = op.replace("_cs", "").replace("has", "contains")
                cmp = Cmp(fld, base, value, not op.endswith("_cs"))
            return Not(cmp) if neg else cmp
        if tok.kind == "OP":
            val = self.s.next()
            if val.kind == "NUMBER":
                value = _num(val.val)
            elif val.kind == "STRING":
                value = _kql_str(val)
            elif val.kind == "IDENT" and val.val in ("true", "false"):
                value = val.val == "true"
            else:
                raise ConversionError(f"unsupported KQL value {val.val!r}")
            ops = {"==": ("eq", False), "=~": ("eq", True), "!=": ("ne", False), "!~": ("ne", True),
                   ">": ("gt", False), ">=": ("ge", False), "<": ("lt", False), "<=": ("le", False)}
            if tok.val not in ops:
                raise ConversionError(f"unsupported KQL operator {tok.val!r}")
            op, nc = ops[tok.val]
            return Cmp(fld, op, value, (nc or nocase_hint) and isinstance(value, str))
        raise ConversionError(f"unsupported KQL operator {tok.val!r}")


def _split(toks: list[Tok], kind: str = "PIPE") -> list[list[Tok]]:
    segs, cur, depth = [], [], 0
    for t in toks:
        depth += t.kind in ("LP", "LB")
        depth -= t.kind in ("RP", "RB")
        if t.kind == kind and depth == 0:
            segs.append(cur)
            cur = []
        else:
            cur.append(t)
    segs.append(cur)
    return segs


def parse_kql(text: str) -> Rule:
    rule = Rule()
    segs = _split(tokenize(text.strip(), KQL_SPEC))
    head = segs[0]
    if not head or head[0].kind != "IDENT":
        raise ConversionError("KQL query must start with a table or function name")
    table = head[0].val
    rule.source_hint["kql_table"] = table
    rule.category = F.KQL_TABLE_CATEGORY.get(table.lower(), "generic")
    conds, agg, aliases = [], None, {}
    for seg in segs[1:]:
        if not seg:
            continue
        cmd, rest = seg[0].val.lower(), seg[1:]
        if cmd in ("where", "filter"):
            if agg is not None and rest and rest[0].kind == "IDENT" and rest[0].val in aliases:
                if len(rest) != 3 or rest[1].kind != "OP" or rest[2].kind != "NUMBER":
                    raise ConversionError("only '<count> <op> <number>' is supported after summarize")
                kind = aliases[rest[0].val]
                agg.op, agg.threshold = ("=" if rest[1].val == "==" else rest[1].val), int(rest[2].val)
                if kind != "count":
                    agg.distinct_field = "@" + kind
                continue
            conds.append(_KqlExpr(rest, rule).parse())
        elif cmd == "summarize":
            agg = Aggregation()
            parts = _split(rest, "COMMA")
            by_idx = None
            flat = rest
            for i, t in enumerate(flat):
                if t.kind == "IDENT" and t.val.lower() == "by":
                    by_idx = i
            aggs = _split(flat[:by_idx] if by_idx is not None else flat, "COMMA")
            for a in aggs:
                if not a:
                    continue
                alias = None
                if len(a) > 2 and a[1].kind == "OP" and a[1].val == "=":
                    alias, a = a[0].val, a[2:]
                fn = a[0].val.lower()
                if fn == "count":
                    aliases[alias or "count_"] = "count"
                elif fn == "dcount":
                    fld = a[2].val
                    aliases[alias or f"dcount_{fld}"] = fld
                else:
                    rule.warn(f"aggregation {fn}() is not supported and was ignored")
            if by_idx is not None:
                for g in _split(flat[by_idx + 1:], "COMMA"):
                    if g and g[0].val.lower() == "bin":
                        agg.window = norm_window(g[-2].val)
                    elif g:
                        agg.group_by.append("@" + g[0].val)
            del parts
        elif cmd in ("project", "project-away", "extend", "sort", "order", "take", "limit", "top", "distinct"):
            rule.warn(f"'{cmd}' stage ignored (presentation only)")
        else:
            raise ConversionError(f"KQL operator '{cmd}' is not supported")
    rule.condition = and_(conds)
    rule.aggregation = agg
    return _finalize(rule, "kql")


# =========================================================================== SPL

SPL_SEARCH_SPEC = [
    ("WS", r"\s+"),
    ("STRING", r'"(?:\\.|[^"\\])*"'),
    ("LP", r"\("), ("RP", r"\)"), ("COMMA", r","),
    ("OP", r"!=|<=|>=|==|=|<|>"),
    ("WORD", r"[^\s()=!<>\",]+"),
]
SPL_EVAL_SPEC = [
    ("WS", r"\s+"),
    ("STRING", r'"(?:\\.|[^"\\])*"'),
    ("NUMBER", r"\d+(?:\.\d+)?(?![\w.])"),
    ("OP", r"!=|<=|>=|==|=|<|>"),
    ("LP", r"\("), ("RP", r"\)"), ("COMMA", r","),
    ("IDENT", r"'[^']+'|[A-Za-z_][\w.]*"),
]
SPL_META_FIELDS = {"index", "sourcetype", "source", "eventtype", "earliest", "latest"}


def _split_pipes(text: str) -> list[str]:
    out, cur, q, i = [], [], False, 0
    while i < len(text):
        c = text[i]
        if c == "\\" and q and i + 1 < len(text):
            cur.append(text[i:i + 2])
            i += 2
            continue
        if c == '"':
            q = not q
        if c == "|" and not q:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    out.append("".join(cur).strip())
    return out


class _SplSearch:
    def __init__(self, text: str, rule: Rule):
        self.s, self.rule = Stream(tokenize(text, SPL_SEARCH_SPEC)), rule

    def parse(self):
        items = []
        while not self.s.done():
            items.append(self.or_expr())
        return and_(items)

    def or_expr(self):
        parts = [self.and_expr()]
        while self.s.at("WORD", "OR", ci=False):
            self.s.next()
            parts.append(self.and_expr())
        return or_(parts)

    def and_expr(self):
        parts = [self.unary()]
        while not self.s.done() and not self.s.at("RP") and not self.s.at("WORD", "OR", ci=False):
            if self.s.at("WORD", "AND", ci=False):
                self.s.next()
            parts.append(self.unary())
        return and_(parts)

    def unary(self):
        if self.s.at("WORD", "NOT", ci=False):
            self.s.next()
            inner = self.unary()
            return Not(inner) if inner is not None else None
        if self.s.at("LP"):
            self.s.next()
            items = []
            while not self.s.at("RP"):
                items.append(self.or_expr())
            self.s.expect("RP")
            return and_(items)
        return self.term()

    def term(self):
        tok = self.s.next()
        if tok.kind == "STRING" or not (self.s.at("OP") or self.s.at("WORD", "IN")):
            self.rule.warn(f"free-text search term {tok.val!r} cannot be mapped to a field and was dropped")
            return None
        name = tok.val
        if self.s.at("WORD", "IN"):
            self.s.next()
            self.s.expect("LP")
            vals = []
            while not self.s.at("RP"):
                v = self.s.next()
                if v.kind in ("STRING", "WORD"):
                    vals.append(_unescape(v.val[1:-1]) if v.kind == "STRING" else v.val)
            self.s.expect("RP")
            return Cmp("@" + name, "in", vals, True)
        op = self.s.next().val
        v = self.s.next()
        value = _unescape(v.val[1:-1]) if v.kind == "STRING" else v.val
        low = name.lower()
        if low in SPL_META_FIELDS:
            self.rule.source_hint.setdefault("spl", []).append(f"{name}={v.val}")
            return None
        if low == "tag":
            cat = F.SPL_TAG_CATEGORY.get(value.lower())
            if cat and (self.rule.category == "generic" or cat == "dns"):
                self.rule.category = cat
            return None
        if op in (">", ">=", "<", "<=") and re.fullmatch(r"\d+(\.\d+)?", value):
            return Cmp("@" + name, CMP_OPS[op], _num(value), False)
        if CIDR_RE.match(value):
            cmp = Cmp("@" + name, "cidr", value, False)
        else:
            cmp = wildcard_to_cmp("@" + name, value, "*", None, True)
        return Not(cmp) if op == "!=" else cmp


class _SplEval(_KqlExpr):
    """`| where` eval expressions (AND / OR / NOT, match(), like(), cidrmatch())."""

    def __init__(self, text: str, rule: Rule):
        self.s, self.rule = Stream(tokenize(text, SPL_EVAL_SPEC)), rule

    def unary(self):
        if self.s.at_word("not"):
            self.s.next()
            return Not(self.unary())
        if self.s.at("LP"):
            self.s.next()
            inner = self.or_expr()
            self.s.expect("RP")
            return inner
        name = self.s.expect("IDENT").val.strip("'")
        if self.s.at("LP"):
            return self.function(name)
        op = self.s.expect("OP").val
        val = self.s.next()
        value = _num(val.val) if val.kind == "NUMBER" else _unescape(val.val[1:-1]) if val.kind == "STRING" else val.val
        return Cmp("@" + name, CMP_OPS[op], value, False)

    def _arg(self) -> tuple[str, bool]:
        """One function argument -> (value, wrapped_in_lower_or_upper)."""
        t = self.s.next()
        if t.kind == "IDENT" and t.val.lower() in ("lower", "upper") and self.s.at("LP"):
            self.s.next()
            inner = self.s.expect("IDENT").val.strip("'")
            self.s.expect("RP")
            return inner, True
        if t.kind == "STRING":
            return _unescape(t.val[1:-1]), False
        return t.val.strip("'"), False

    def function(self, name: str):
        self.s.expect("LP")
        args = []
        while not self.s.at("RP"):
            if self.s.at("COMMA"):
                self.s.next()
                continue
            args.append(self._arg())
        self.s.expect("RP")
        low = name.lower()
        vals = [a[0] for a in args]
        folded = bool(args) and args[0][1]
        if low == "match" and len(args) == 2:
            return regex_to_cmp("@" + vals[0], vals[1], folded)
        if low == "like" and len(args) == 2:
            return wildcard_to_cmp("@" + vals[0], vals[1], "%", "_", folded)
        if low == "cidrmatch" and len(args) == 2:
            return Cmp("@" + vals[1], "cidr", vals[0], False)
        if low in ("isnotnull", "isnull") and len(args) == 1:
            return Cmp("@" + vals[0], "ne" if low == "isnotnull" else "eq", "", False)
        if low == "in" and len(args) >= 2:
            return Cmp("@" + vals[0], "in", vals[1:], folded)
        if low in ("lower", "upper") and len(args) == 1:
            op = self.s.expect("OP").val
            val = self.s.next()
            v = _unescape(val.val[1:-1]) if val.kind == "STRING" else val.val
            return Cmp("@" + vals[0], CMP_OPS[op], v, True)
        raise ConversionError(f"SPL eval function {name}() is not supported")


def parse_spl(text: str) -> Rule:
    rule = Rule()
    stages = _split_pipes(text.strip())
    first = re.sub(r"^\s*search\s+", "", stages[0], flags=re.I)
    conds = [_SplSearch(first, rule).parse()] if first else []
    agg, aliases, window = None, {}, None
    for st in stages[1:]:
        cmd, _, args = st.partition(" ")
        cmd = cmd.lower()
        if cmd == "search":
            conds.append(_SplSearch(args, rule).parse())
        elif cmd == "where":
            m = re.fullmatch(r"\s*'?(\w+)'?\s*(>=|>|==|=|<=|<)\s*(\d+)\s*", args)
            if agg is not None and m and m.group(1) in aliases:
                agg.op, agg.threshold = ("=" if m.group(2) == "==" else m.group(2)), int(m.group(3))
                if aliases[m.group(1)] != "count":
                    agg.distinct_field = "@" + aliases[m.group(1)]
            else:
                conds.append(_SplEval(args, rule).parse())
        elif cmd == "regex":
            m = re.fullmatch(r'\s*(\w+)\s*(!?=)\s*"((?:\\.|[^"\\])*)"\s*', args)
            if not m:
                raise ConversionError(f"unsupported regex command: {st!r}")
            cmp = regex_to_cmp("@" + m.group(1), m.group(3).replace('\\"', '"'), False)
            conds.append(Not(cmp) if m.group(2) == "!=" else cmp)
        elif cmd in ("bin", "bucket"):
            m = re.search(r"span\s*=\s*(\d+[smhd])", args)
            if m:
                window = norm_window(m.group(1))
        elif cmd == "stats":
            agg = Aggregation()
            head, _, by = re.split(r"\s+by\s+", args, maxsplit=1, flags=re.I)[0], None, None
            parts = re.split(r"\s+by\s+", args, maxsplit=1, flags=re.I)
            head = parts[0]
            by = parts[1] if len(parts) > 1 else ""
            for fn, fld, alias in re.findall(r"(count|dc|distinct_count)(?:\((\w*)\))?(?:\s+as\s+(\w+))?", head, re.I):
                if fn.lower() == "count":
                    aliases[alias or "count"] = "count"
                else:
                    aliases[alias or f"dc({fld})"] = fld
            agg.group_by = ["@" + g for g in re.split(r"[\s,]+", by.strip()) if g and g != "_time"]
        elif cmd in ("table", "fields", "sort", "rename", "head", "dedup", "eval"):
            rule.warn(f"'{cmd}' stage ignored (presentation only)")
        else:
            raise ConversionError(f"SPL command '{cmd}' is not supported")
    if agg:
        agg.window = window
    rule.condition = and_(conds)
    rule.aggregation = agg
    return _finalize(rule, "spl")


# =========================================================================== AQL

AQL_SPEC = [
    ("WS", r"\s+"),
    ("STRING", r"'(?:[^']|'')*'"),
    ("DQ", r'"[^"]*"'),
    ("NUMBER", r"\d+(?:\.\d+)?(?![\w.])"),
    ("OP", r"!=|<>|<=|>=|=|<|>"),
    ("LP", r"\("), ("RP", r"\)"), ("COMMA", r","), ("STAR", r"\*"),
    ("IDENT", r"[A-Za-z_][\w.]*"),
]
AQL_CLAUSES = {"select", "from", "where", "group", "having", "order", "last", "start", "stop", "limit"}


def _aql_str(t: Tok) -> str:
    return t.val[1:-1].replace("''", "'")


class _AqlExpr(_KqlExpr):
    def __init__(self, toks: list[Tok], rule: Rule):
        self.s, self.rule = Stream(toks), rule

    def unary(self):
        if self.s.at_word("not"):
            self.s.next()
            return Not(self.unary())
        if self.s.at("LP"):
            self.s.next()
            inner = self.or_expr()
            self.s.expect("RP")
            return inner
        if self.s.at_word("incidr"):
            self.s.next()
            self.s.expect("LP")
            cidr = _aql_str(self.s.expect("STRING"))
            self.s.expect("COMMA")
            fld = self.field()
            self.s.expect("RP")
            return Cmp("@" + fld, "cidr", cidr, False)
        fld = "@" + self.field()
        neg = False
        if self.s.at_word("not"):
            self.s.next()
            neg = True
        tok = self.s.next()
        word = tok.val.lower()
        if word in ("ilike", "like"):
            cmp = wildcard_to_cmp(fld, _aql_str(self.s.expect("STRING")), "%", "_", word == "ilike")
        elif word in ("imatches", "matches"):
            cmp = regex_to_cmp(fld, _aql_str(self.s.expect("STRING")), word == "imatches")
        elif word == "in":
            self.s.expect("LP")
            vals = []
            while not self.s.at("RP"):
                t = self.s.next()
                if t.kind == "STRING":
                    vals.append(_aql_str(t))
                elif t.kind == "NUMBER":
                    vals.append(_num(t.val))
            self.s.expect("RP")
            cmp = Cmp(fld, "in", vals, False)
        elif word == "is":
            isnot = self.s.at_word("not") and bool(self.s.next())
            self.s.expect("IDENT", "null")
            cmp = Cmp(fld, "ne" if isnot else "eq", "", False)
        elif tok.kind == "OP":
            v = self.s.next()
            value = _num(v.val) if v.kind == "NUMBER" else _aql_str(v) if v.kind == "STRING" else v.val
            cmp = Cmp(fld, CMP_OPS[tok.val], value, False)
        else:
            raise ConversionError(f"unsupported AQL operator {tok.val!r}")
        return Not(cmp) if neg else cmp

    def field(self) -> str:
        t = self.s.next()
        if t.kind == "DQ":
            return t.val[1:-1]
        if t.kind == "IDENT" and self.s.at("LP"):
            self.s.next()
            inner = []
            while not self.s.at("RP"):
                inner.append(self.s.next().val)
            self.s.next()
            return f"{t.val}({''.join(inner)})"
        if t.kind == "IDENT":
            return t.val
        raise ConversionError(f"expected AQL field, got {t.val!r}")


def parse_aql(text: str) -> Rule:
    rule = Rule()
    toks = tokenize(text.strip().rstrip(";"), AQL_SPEC)
    clauses: dict[str, list[Tok]] = {}
    cur, depth = None, 0
    for t in toks:
        depth += t.kind == "LP"
        depth -= t.kind == "RP"
        if depth == 0 and t.kind == "IDENT" and t.val.lower() in AQL_CLAUSES:
            cur = t.val.lower()
            clauses[cur] = []
            continue
        if cur and not (cur in ("group", "order") and not clauses[cur] and t.val.lower() == "by"):
            clauses[cur].append(t)
    if "from" in clauses and clauses["from"] and clauses["from"][0].val.lower() == "flows":
        rule.warn("query targets flows; converted fields assume event data")
    if clauses.get("where"):
        rule.condition = _AqlExpr(clauses["where"], rule).parse()
    if "group" in clauses or "having" in clauses:
        agg = Aggregation()
        for g in _split(clauses.get("group", []), "COMMA"):
            if g:
                agg.group_by.append("@" + (g[0].val[1:-1] if g[0].kind == "DQ" else "".join(t.val for t in g)))
        hv = clauses.get("having", [])
        if hv:
            fn = hv[0].val.lower()
            i = next(k for k, t in enumerate(hv) if t.kind == "OP")
            agg.op, agg.threshold = ("=" if hv[i].val == "=" else hv[i].val), int(hv[i + 1].val)
            if fn == "uniquecount":
                arg = hv[2]
                agg.distinct_field = "@" + (arg.val[1:-1] if arg.kind == "DQ" else arg.val)
        rule.aggregation = agg
    last = clauses.get("last")
    if last and len(last) >= 2 and rule.aggregation:
        rule.aggregation.window = norm_window(last[0].val, last[1].val)
    return _finalize(rule, "aql")


PARSERS = {"yaral": parse_yaral, "kql": parse_kql, "spl": parse_spl, "aql": parse_aql}
