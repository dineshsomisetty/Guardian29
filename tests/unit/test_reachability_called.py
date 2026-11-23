"""Stretch goal 1: function-level reachability ("called") for reviewed advisories, never "not called"."""

from guardian.agents.risk_analyst import called_for
from guardian.core.models import Finding, FindingCategory
from guardian.tools import reachability as reach


def _write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def test_call_sites_follow_local_names_and_ignore_tests(tmp_path):
    reach._INDEX.clear()
    _write(tmp_path, "lib/auth.ts", "import jwt from 'jsonwebtoken'\nexport const v = (t) => jwt.verify(t, key)\n")
    _write(tmp_path, "lib/cast.ts", "import jws from 'jws'\nexport const v = (t) => (jws.verify as Fn)(t, k)\n")
    _write(tmp_path, "routes/eval.ts", "import { eval as safeEval } from 'notevil'\nrun('safeEval(x)')\n")
    _write(tmp_path, "routes/req.js", "const { verify: check } = require('jsonwebtoken')\ncheck(token)\n")
    _write(tmp_path, "lib/assign.ts", "import jws from 'jws'\njws.verify = patched\n")  # an assignment is not a use
    _write(tmp_path, "test/auth.test.ts", "import jwt from 'jsonwebtoken'\njwt.verify(t)\n")  # tests excluded
    sites = reach.call_sites(tmp_path, "jsonwebtoken", ["verify"])
    assert {(s["file"], s["line"]) for s in sites} == {("lib/auth.ts", 2), ("routes/req.js", 2)}
    assert [(s["file"], s["line"]) for s in reach.call_sites(tmp_path, "jws", ["verify"])] == [("lib/cast.ts", 2)]
    assert [s["function"] for s in reach.call_sites(tmp_path, "notevil", ["__call__", "eval"])] == ["eval"]
    assert reach.call_sites(tmp_path, "lodash", ["template"]) == []


def test_called_tier_only_for_the_advisories_a_rule_covers():
    def cve(vid, aliases=()):
        return Finding(run_id="r", category=FindingCategory.CVE, title="t", detector="grype", vuln_id=vid,
                       aliases=list(aliases), evidence_ids=["ev_1"])

    called = [{"vuln_ids": ["GHSA-c7hr-j4mj-j2w6"], "sites": [{"file": "a.ts", "line": 1}]}]
    assert called_for(called, cve("GHSA-c7hr-j4mj-j2w6"))
    assert called_for(called, cve("CVE-2015-9235", ["GHSA-c7hr-j4mj-j2w6"]))
    assert not called_for(called, cve("GHSA-other"))  # another advisory of the same package stays "imported"
    assert called_for([{"vuln_ids": ["*"], "sites": [{"file": "b.ts"}]}], cve("GHSA-any"))
    assert not called_for([{"vuln_ids": ["*"], "sites": []}], cve("GHSA-any"))


def test_rules_file_is_valid():
    for pkg in ("jsonwebtoken", "jws", "express-jwt", "sanitize-html", "notevil", "lodash"):
        rules = reach.vulnerable_functions(pkg)
        assert rules and all(r["vuln_ids"] and r["functions"] and r["why"] for r in rules), pkg
