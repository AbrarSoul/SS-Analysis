"""
Pipeline test for FINAL-set cases (Step 2 of the post-Section-9 plan): runs hand-written "gold" Semgrep
rules through the real evaluate_case_bundle() scorer and prints the six-sample outcomes per case, plus two
invariant rules (match-nothing, match-everything) that bound the scorer. No LLM and no API key involved.

Run with the project venv first on PATH so `semgrep` resolves to the pinned version:
    PATH=.venv/bin:$PATH python pipeline/tests/run_gold_rules_final.py
"""
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("GPTLAB_API_KEY", "not-used-in-this-test")  # build_config() insists on one; never sent anywhere
ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "pipeline"), str(ROOT / "autogrep")]

import yaml  # noqa: E402
from gptlab_config import build_config  # noqa: E402
from rule_validator import RuleValidator  # noqa: E402
from run_generation import _load_frozen_manifest_index  # noqa: E402
from sample_evaluation import evaluate_case_bundle  # noqa: E402

EXPECTED = {  # ideal outcome per sample for a rule that captures the mechanism and discriminates perfectly
    "original_vulnerable": "TP", "original_patched": "TN", "variant_vulnerable_1": "TP",
    "variant_vulnerable_2": "TP", "variant_safe": "TN", "benign_lookalike": "TN",
}
LANG_KEY = {"python": "python", "java": "java", "javascript": "javascript", "typescript": "typescript"}


def main():
    cfg = build_config("qwen2.5-coder:7b-instruct")
    rv = RuleValidator(cfg)
    manifest = _load_frozen_manifest_index(ROOT / "benchmark")
    rows = []
    for rule_file in sorted((ROOT / "pipeline" / "tests" / "gold_rules_final").glob("CASE-*.yml")):
        cid = rule_file.stem
        rule = yaml.safe_load(rule_file.read_text())["rules"][0]
        meta = json.loads((ROOT / "benchmark" / "cases" / cid / "metadata.json").read_text())
        lang = meta["language"]
        recs, err = evaluate_case_bundle(rule, ROOT / "benchmark" / "cases" / cid, lang, rv, "gold", cid, "gold-rule",
                                         "gold", vulnerable_lines=manifest[cid].get("vulnerable_lines"))
        rows.append((cid, meta["semgrep_representability"], recs, err))
        for kind, pattern in (("match-nothing", "$X.__no_such_attribute_zzz__"), ("match-everything", "$X")):
            inv = {"id": f"invariant-{kind}", "message": "m", "severity": "INFO", "languages": [LANG_KEY[lang]],
                   "pattern": pattern}
            irecs, ierr = evaluate_case_bundle(inv, ROOT / "benchmark" / "cases" / cid, lang, rv, "gold", cid, kind, kind)
            rows.append((f"{cid}:{kind}", meta["semgrep_representability"], irecs, ierr))
    for cid, status, recs, err in rows:
        by = {r.sample_type: r for r in recs}
        cells = " ".join(f"{k.replace('variant_','v').replace('original_','o')[:9]:9}={by[k].outcome if k in by else '--'}{'*' if k in by and by[k].finding_location_correct else ''}"
                         for k in EXPECTED)
        ideal = all(k in by and by[k].outcome == v for k, v in EXPECTED.items())
        print(f"{cid:28} {status:19} {cells}  {'IDEAL' if ideal else ''}{'  ERR:' + str(err)[:60] if err else ''}")
    print("\n(* = finding located inside the labelled vulnerable region)")


if __name__ == "__main__":
    main()
