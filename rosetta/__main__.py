"""Command-line interface.

    python -m rosetta convert --from spl --to kql query.spl
    python -m rosetta convert --to all rule.yaral          # source inferred from extension
    echo 'index=* EventCode=4625' | python -m rosetta convert --from spl --to yaral -
    python -m rosetta batch --from yaral --to kql,spl,aql --in rules/ --out translated/
    python -m rosetta fields
"""
from __future__ import annotations

import argparse
import re
import copy
import sys
from collections import Counter
from pathlib import Path

from . import LANGUAGE_NAMES, LANGUAGES, __version__, parse, render
from .fields import field_table
from .ir import ConversionError

EXT = {".yaral": "yaral", ".yl": "yaral", ".kql": "kql", ".spl": "spl", ".aql": "aql"}
COMMENT = {"yaral": "//", "kql": "//", "spl": "```", "aql": None}


def _targets(value: str, source: str) -> list[str]:
    if value == "all":
        return [t for t in LANGUAGES if t != source]
    out = [t.strip() for t in value.split(",")]
    bad = [t for t in out if t not in LANGUAGES]
    if bad:
        raise SystemExit(f"unknown target(s): {', '.join(bad)}")
    return out


def _source_for(path: str, explicit: str | None) -> str:
    if explicit:
        return explicit
    src = EXT.get(Path(path).suffix.lower())
    if not src:
        raise SystemExit(f"cannot infer source language of {path}; pass --from")
    return src


def cmd_convert(args) -> int:
    rc = 0
    for path in args.files:
        source = _source_for(path, args.source) if path != "-" else (args.source or "")
        if not source:
            raise SystemExit("--from is required when reading stdin")
        text = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
        try:
            rule = parse(text, source)
        except ConversionError as e:
            print(f"✗ {path}: {e}", file=sys.stderr)
            rc = 1
            continue
        for w in rule.warnings:
            print(f"  ⚠ {w}", file=sys.stderr)
        seen = set(rule.warnings)
        for target in _targets(args.target, source):
            r = copy.deepcopy(rule)
            try:
                out = render(r, target)
            except ConversionError as e:
                print(f"✗ {path} -> {target}: {e}", file=sys.stderr)
                rc = 1
                continue
            if len(args.files) > 1 or "," in args.target or args.target == "all":
                print(f"===== {path} -> {LANGUAGE_NAMES[target]} =====")
            print(out.rstrip())
            for w in r.warnings:
                if w not in seen:
                    print(f"  ⚠ [{target}] {w}", file=sys.stderr)
            print()
    return rc


def cmd_batch(args) -> int:
    src_dir, out_dir = Path(args.indir), Path(args.outdir)
    exts = [e for e, lang in EXT.items() if lang == args.source]
    files = sorted(p for p in src_dir.rglob("*") if p.suffix.lower() in exts)
    targets = _targets(args.target, args.source)
    stats = {t: Counter() for t in targets}
    failures, warn_counter = [], Counter()
    for f in files:
        rel = f.relative_to(src_dir)
        try:
            rule = parse(f.read_text(encoding="utf-8"), args.source)
        except Exception as e:  # noqa: BLE001 - report, never crash a batch
            failures.append((rel.as_posix(), "parse", f"{type(e).__name__}: {e}" if not isinstance(e, ConversionError) else str(e)))
            for t in targets:
                stats[t]["failed"] += 1
            continue
        for t in targets:
            r = copy.deepcopy(rule)
            try:
                out = render(r, t)
            except Exception as e:  # noqa: BLE001
                failures.append((rel.as_posix(), t, str(e) if isinstance(e, ConversionError) else f"{type(e).__name__}: {e}"))
                stats[t]["failed"] += 1
                continue
            stats[t]["converted"] += 1
            if r.warnings:
                stats[t]["with_warnings"] += 1
            for w in r.warnings:
                warn_counter[re.sub(r"'[^']*'", "<x>", w)] += 1
            dest = out_dir / t / rel.with_suffix(f".{t}")
            dest.parent.mkdir(parents=True, exist_ok=True)
            c = COMMENT[t]
            header = ""
            if r.warnings and c:
                end = c if c == "```" else ""
                header = "".join(f"{c} WARNING: {w} {end}\n" for w in r.warnings)
            dest.write_text(header + out, encoding="utf-8", newline="\n")

    lines = [f"# Batch conversion report ({args.source} → {', '.join(targets)})", "",
             f"Source files: **{len(files)}**", "",
             "| Target | Converted | With warnings | Failed |", "|---|---:|---:|---:|"]
    for t in targets:
        s = stats[t]
        lines.append(f"| {LANGUAGE_NAMES[t]} | {s['converted']} | {s['with_warnings']} | {s['failed']} |")
    if failures:
        lines += ["", "## Not converted", "", "| File | Stage | Reason |", "|---|---|---|"]
        lines += [f"| `{f}` | {stage} | {reason} |" for f, stage, reason in failures]
    if warn_counter:
        lines += ["", "## Most common warnings", "", "| Warning | Count |", "|---|---:|"]
        lines += [f"| {w} | {n} |" for w, n in warn_counter.most_common(15)]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(lines[:6 + len(targets)]))
    print(f"\nFull report: {out_dir / 'REPORT.md'}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="rosetta", description="Translate detection queries between SIEM languages.")
    ap.add_argument("--version", action="version", version=f"rosetta-siem {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("convert", help="convert one or more files (or - for stdin)")
    c.add_argument("--from", dest="source", choices=LANGUAGES)
    c.add_argument("--to", dest="target", required=True, help="target language, comma list, or 'all'")
    c.add_argument("files", nargs="+")
    c.set_defaults(func=cmd_convert)

    b = sub.add_parser("batch", help="convert a whole directory and write a report")
    b.add_argument("--from", dest="source", choices=LANGUAGES, required=True)
    b.add_argument("--to", dest="target", required=True)
    b.add_argument("--in", dest="indir", required=True)
    b.add_argument("--out", dest="outdir", required=True)
    b.set_defaults(func=cmd_batch)

    fl = sub.add_parser("fields", help="print the field mapping table")
    fl.set_defaults(func=lambda a: print(field_table()) or 0)

    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
