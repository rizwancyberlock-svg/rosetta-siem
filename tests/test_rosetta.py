"""Tests for rosetta-siem. Run: python -m unittest discover -s tests -v"""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from rosetta import ConversionError, convert, parse, render  # noqa: E402
from rosetta.ir import Aggregation, And, Cmp, Not, Or, Rule  # noqa: E402

YARAL = r'''
rule win_test_encoded_powershell {
  meta:
    description = "Encoded PowerShell"
    severity = "HIGH"
    mitre_attack_tactic = "Execution"
    mitre_attack_technique = "T1059.001"
  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /\\powershell\.exe$/ nocase
    (
      $e.target.process.command_line = /-enc/ nocase or
      $e.target.process.command_line = /frombase64string/ nocase
    )
    not $e.principal.user.userid = "SYSTEM"
  condition:
    $e
}
'''

YARAL_AGG = r'''
rule spray {
  events:
    $e.metadata.event_type = "USER_LOGIN"
    $e.security_result.action = "BLOCK"
    $e.principal.ip = $ip
    $e.target.user.userid = $user
  match:
    $ip over 30m
  condition:
    #user >= 15
}
'''


class ParseTests(unittest.TestCase):
    def test_yaral(self):
        r = parse(YARAL, "yaral")
        self.assertEqual(r.name, "win_test_encoded_powershell")
        self.assertEqual(r.category, "process")
        self.assertEqual(r.techniques, ["T1059.001"])
        self.assertEqual(r.condition, And([
            Cmp("process.path", "endswith", "\\powershell.exe", True),
            Or([Cmp("process.command_line", "contains", "-enc", True),
                Cmp("process.command_line", "contains", "frombase64string", True)]),
            Not(Cmp("user.name", "eq", "SYSTEM", False)),
        ]))

    def test_yaral_aggregation(self):
        r = parse(YARAL_AGG, "yaral")
        self.assertEqual(r.category, "authentication")
        self.assertEqual(r.condition, Cmp("event.outcome", "eq", "failure", False))
        self.assertEqual(r.aggregation, Aggregation(["source.ip"], "30m", "target.user.name", ">=", 15))

    def test_yaral_multi_event_rejected(self):
        text = 'rule x { events:\n $a.metadata.id = $id\n $b.metadata.id = $id\n match:\n $id over 1h\n condition:\n $a and $b }'
        with self.assertRaises(ConversionError):
            parse(text, "yaral")

    def test_spl(self):
        r = parse('index=win EventCode=4688 (process_name="powershell.exe" OR process_name="pwsh.exe") '
                  'process="*-enc*" NOT user=SYSTEM', "spl")
        self.assertEqual(r.category, "process")  # inferred from EventCode 4688
        self.assertIn(Cmp("process.command_line", "contains", "-enc", True), r.condition.items)
        self.assertEqual(r.source_hint["spl"], ["index=win"])

    def test_spl_stats(self):
        r = parse('tag=authentication action=failure | bin _time span=30m '
                  '| stats count dc(user) as users by src | where users>=15', "spl")
        self.assertEqual(r.aggregation, Aggregation(["source.ip"], "30m", "target.user.name", ">=", 15))

    def test_spl_regex_command(self):
        r = parse('index=* | regex CommandLine="(?i)invoke-(mimikatz|kerberoast)"', "spl")
        self.assertEqual(r.condition, Cmp("process.command_line", "regex", "invoke-(mimikatz|kerberoast)", True))

    def test_kql(self):
        r = parse('DeviceProcessEvents\n| where FileName in~ ("powershell.exe", "pwsh.exe")\n'
                  '    and ProcessCommandLine has_any ("-enc", "-e ")\n| project Timestamp', "kql")
        self.assertEqual(r.category, "process")
        self.assertEqual(r.condition.items[0], Cmp("process.name", "in", ["powershell.exe", "pwsh.exe"], True))
        self.assertIsInstance(r.condition.items[1], Or)

    def test_kql_summarize(self):
        r = parse('_Im_Authentication | where EventResult == "Failure" '
                  '| summarize c = count(), u = dcount(TargetUsername) by SrcIpAddr, bin(TimeGenerated, 1h) '
                  '| where u > 10', "kql")
        self.assertEqual(r.aggregation, Aggregation(["source.ip"], "1h", "target.user.name", ">", 10))
        self.assertEqual(r.condition, Cmp("event.outcome", "eq", "failure", False))

    def test_aql(self):
        r = parse("SELECT sourceip, COUNT(*) FROM events WHERE \"EventID\" = '4625' "
                  "AND username NOT ILIKE '%$' AND INCIDR('10.0.0.0/8', sourceip) "
                  "GROUP BY sourceip HAVING COUNT(*) >= 20 LAST 15 MINUTES", "aql")
        self.assertEqual(r.category, "authentication")
        self.assertEqual(r.aggregation, Aggregation(["source.ip"], "15m", None, ">=", 20))
        self.assertIn(Cmp("source.ip", "cidr", "10.0.0.0/8", False), r.condition.items)
        self.assertIn(Not(Cmp("target.user.name", "endswith", "$", False)), r.condition.items)


class RenderTests(unittest.TestCase):
    def test_yaral_to_kql(self):
        out, _ = convert(YARAL, "yaral", "kql")
        self.assertTrue(out.startswith("_Im_ProcessCreate"))
        self.assertIn('TargetProcessName endswith "\\\\powershell.exe"', out)
        self.assertIn('not(ActorUsername == "SYSTEM")', out)

    def test_yaral_to_spl_and_aql(self):
        spl, _ = convert(YARAL_AGG, "yaral", "spl")
        self.assertIn("tag=authentication", spl)
        self.assertIn("dc(user) AS distinct_count BY _time src", spl)
        aql, _ = convert(YARAL_AGG, "yaral", "aql")
        self.assertIn("HAVING UNIQUECOUNT(username) >= 15", aql)
        self.assertIn("LAST 30 MINUTES", aql)

    def test_numeric_fields_unquoted(self):
        out, _ = convert('index=* dest_port="445"', "spl", "yaral")
        self.assertIn("$e.target.port = 445", out)

    def test_unmapped_field_warns(self):
        _, warnings = convert('SigninLogs | where ResultType != "0"', "kql", "yaral")
        self.assertTrue(any("ResultType" in w for w in warnings))

    def test_name_to_path(self):
        out, warnings = convert('index=* process_name="cmd.exe"', "spl", "yaral")
        self.assertIn("/cmd\\.exe$/", out)
        self.assertTrue(any("ends-with" in w for w in warnings))


def _canon(e, ignore_case=False):
    """Order-insensitive, optionally case-insensitive representation of an expression."""
    if isinstance(e, Cmp):
        return ("cmp", e.field, e.op, repr(e.value), False if ignore_case else e.nocase)
    if isinstance(e, Not):
        return ("not", _canon(e.item, ignore_case))
    kind = "and" if isinstance(e, And) else "or"
    return (kind, tuple(sorted((_canon(i, ignore_case) for i in e.items), key=repr)))


class RoundTripTests(unittest.TestCase):
    """parse(render(rule)) must give back the same rule, for every language."""

    SAMPLES = [
        Rule(category="process", condition=And([
            Cmp("process.path", "endswith", "\\rundll32.exe", True),
            Or([Cmp("process.command_line", "contains", "javascript:", True),
                Cmp("process.command_line", "regex", "https?://[a-z0-9.]+/", True)]),
            Not(Cmp("user.name", "eq", "SYSTEM", True)),
        ])),
        Rule(category="network", condition=And([
            Cmp("destination.port", "eq", 445, False),
            Not(Cmp("destination.ip", "cidr", "10.0.0.0/8", False)),
        ]), aggregation=Aggregation(["source.ip"], "1h", None, ">=", 5)),
        Rule(category="authentication", condition=Cmp("event.outcome", "eq", "failure", False),
             aggregation=Aggregation(["source.ip"], "30m", "target.user.name", ">=", 15)),
    ]

    def _roundtrip(self, lang):
        # AQL has no event category, so QRadar's single `username` property cannot
        # distinguish actor from target user - a known, documented limitation.
        norm = (lambda f: "user.name" if f == "target.user.name" else f) if lang == "aql" else (lambda f: f)
        for sample in self.SAMPLES:
            rule = copy.deepcopy(sample)
            text = render(rule, lang)
            back = parse(text, lang)
            with self.subTest(lang=lang, text=text):
                # Splunk search is always case-insensitive and may reorder ANDed terms
                ic = lang == "spl"
                self.assertEqual(_canon(back.condition, ic), _canon(sample.condition, ic))
                if lang != "aql":
                    self.assertEqual(back.category, sample.category)
                if sample.aggregation:
                    self.assertEqual(back.aggregation.group_by, sample.aggregation.group_by)
                    self.assertEqual(norm(back.aggregation.distinct_field or ""),
                                     norm(sample.aggregation.distinct_field or ""))
                    self.assertEqual(back.aggregation.threshold, sample.aggregation.threshold)

    def test_yaral(self):
        self._roundtrip("yaral")

    def test_kql(self):
        self._roundtrip("kql")

    def test_spl(self):
        self._roundtrip("spl")

    def test_aql(self):
        self._roundtrip("aql")


class LibraryTests(unittest.TestCase):
    """Convert the open-yaral-detections library if it is checked out next to this repo."""

    def test_library_conversion_rate(self):
        here = Path(__file__).resolve()
        candidates = [here.parents[1] / "open-yaral-detections" / "rules",   # CI checkout
                      here.parents[2] / "open-yaral-detections" / "rules"]   # sibling folder
        lib = next((c for c in candidates if c.is_dir()), None)
        if lib is None:
            self.skipTest("open-yaral-detections not found")
        files = list(lib.rglob("*.yaral"))
        ok = 0
        for f in files:
            try:
                rule = parse(f.read_text(encoding="utf-8"), "yaral")
                for t in ("kql", "spl", "aql"):
                    render(copy.deepcopy(rule), t)
                ok += 1
            except ConversionError:
                pass
        self.assertGreaterEqual(ok / len(files), 0.95, f"only {ok}/{len(files)} rules converted")


if __name__ == "__main__":
    unittest.main()
