"""
2026-10-11: rescore the ALREADY-COMPLETED qwen3_v3 diagnostic run (results/diagnostic_20261010/
qwen3_v3/, the schema-policy-fixed qwen3-coder:30b run on the 24-case development subset) under a
frozen, corrected evaluation setup -- WITHOUT any new model calls. This isolates "did the evaluation
corrections themselves change anything" from "did a revised generation workflow change anything" --
the two must not be conflated, since qwen3_v3 was generated under the OLD evaluation assumptions.

Three corrections applied together, for the first time as one evaluator:
  1. CASE-0298: rescan attempt 1's already-saved rule (results/diagnostic_20261010/qwen3_v3/
     CASE-0298/attempt_1/rule.yml) against .tsx-staged copies instead of the frozen .ts files
     (reuses the exact staged copies + hash proof from pipeline/replay_case0298_tsx.py's output).
     Attempts 2/3 never parsed into a rule at all (confirmed in Qwen3_v3_Review.md), so "iterative"
     has no different candidate to try here -- it reuses the same rescanned attempt 1 result.
  2. CASE-0163/0173/0239/0235 (variant_vulnerable_2): re-derive location-correctness from the
     ALREADY-RECORDED finding_lines using the merged Finding-1 + v2-additive ranges (no rescan
     needed -- this is a pure re-read of existing data, same principle as
     pipeline/rescore_variant_location_v2.py).
  3. Acceptance gate changed from "legacy" (any finding on vulnerable + no finding on patched,
     location-blind) to "corrected" (original-pair LOCATION correctness required: vulnerable
     outcome must be TP, patched outcome must be TN) for every case, including the 19 that were
     never touched by fixes 1/2 -- this can change complete_success denominators even for cases
     with no location-annotation bug, if a case's "acceptance" depended on a location-blind match
     that happens to be outside the annotated range by coincidence.

Scanner failures (scan_ok=False) are kept distinct from genuine non-detections throughout -- a
rescored case where the scan itself still fails is reported as "scan_error", never silently folded
into "FN".

Usage:
    python pipeline/rescore_qwen3_v3_corrected.py
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "pipeline")]
from rescore_variant_location import load_line_ranges
from rescore_variant_location_v2 import load_v2_additions

RUN_NAME = sys.argv[1] if len(sys.argv) > 1 else "qwen3_v3"
RUN_DIR = ROOT / "results/diagnostic_20261010" / RUN_NAME
SELECTION = json.loads((RUN_DIR / "selection.json").read_text())
CASE_IDS = SELECTION["case_ids"]
TSX_STAGE = ROOT / "results/diagnostic_20261010/case0298_tsx_replay_v1/tsx_staged_samples"
SEMGREP = ROOT / ".venv/bin/semgrep"

SAMPLE_ORDER = ["original_vulnerable", "original_patched", "variant_vulnerable_1",
                "variant_vulnerable_2", "variant_safe", "benign_lookalike"]


def rescore_location(samples, extra_ranges, base_ranges, case_id):
    """Apply merged (Finding-1 + v2-additive) ranges to already-recorded finding_lines. Mutates
    nothing outside the returned copy; leaves records with detected=False untouched (a
    non-detection's outcome never depended on location)."""
    out = []
    for s in samples:
        s = dict(s)
        key = (case_id, s["sample_type"])
        if s["sample_type"] in ("variant_vulnerable_1", "variant_vulnerable_2") and s["detected"] and key in extra_ranges:
            all_ranges = list(extra_ranges[key])
            if key in base_ranges:
                all_ranges.append(base_ranges[key])
            lines = s.get("finding_lines") or []
            location_ok = any(any(r[0] <= ln <= r[1] for ln in lines) for r in all_ranges)
            s["finding_location_correct"] = location_ok
            s["outcome"] = "TP" if location_ok else "FN"
        out.append(s)
    return out


def rescan_case0298(attempt1_rule_path):
    import os
    env = os.environ.copy()
    env["PATH"] = str(ROOT / ".venv/bin") + os.pathsep + env.get("PATH", "")
    env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    sample_files = {
        "original_vulnerable": "vulnerable_source", "original_patched": "patched_source",
        "variant_vulnerable_1": "variant_vulnerable_01", "variant_vulnerable_2": "variant_vulnerable_02",
        "variant_safe": "variant_safe_01", "benign_lookalike": "benign_lookalike",
    }
    targets = {k: TSX_STAGE / f"{v}.tsx" for k, v in sample_files.items()}
    cmd = [str(SEMGREP), "--config", str(attempt1_rule_path), "--json", "--metrics=off",
           "--disable-version-check", "--no-git-ignore", "--jobs=1", *[str(p) for p in targets.values()]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, ["Semgrep did not return JSON"]
    errors = data.get("errors", [])
    if proc.returncode:
        errors = [*errors, {"message": f"exit {proc.returncode}"}]
    scan_ok = not errors
    findings = data.get("results", [])

    import sys as _s
    _s.path[:0] = [str(ROOT / "pipeline")]
    from eligible_cases import load_manifest
    manifest = load_manifest()
    ann = {(a["case_id"], a["variant"]): (a["start_line"], a["end_line"])
           for a in map(json.loads, (ROOT / "benchmark/variant_vulnerable_lines.jsonl").read_text().splitlines())}
    v2 = load_v2_additions()

    samples = []
    for kind in SAMPLE_ORDER:
        positive = kind in ("original_vulnerable", "variant_vulnerable_1", "variant_vulnerable_2")
        path = targets[kind]
        found = [r for r in findings if Path(r["path"]).resolve() == path.resolve()]
        lines = [r["start"]["line"] for r in found]
        location = None
        if positive:
            if kind == "original_vulnerable":
                bounds_list = [tuple(manifest["CASE-0298"]["vulnerable_lines"])] if manifest["CASE-0298"].get("vulnerable_lines") else []
            else:
                bounds_list = list(v2.get(("CASE-0298", kind), []))
                base = ann.get(("CASE-0298", kind))
                if base:
                    bounds_list.append(base)
            location = bool(bounds_list and any(any(b[0] <= ln <= b[1] for ln in lines) for b in bounds_list))
        outcome = ("TP" if location else "FN") if positive else ("FP" if found else "TN")
        samples.append({"sample_type": kind, "label": "positive" if positive else "negative",
                         "detected": bool(found), "finding_location_correct": location,
                         "finding_lines": lines, "outcome": outcome})
    return {"scan_ok": scan_ok, "errors": errors, "samples": samples}, None


def corrected_metrics(samples, scan_ok):
    by_type = {s["sample_type"]: s for s in samples}
    vuln, patched = by_type.get("original_vulnerable"), by_type.get("original_patched")
    legacy_accepted = scan_ok and bool(vuln and patched and vuln["detected"] and not patched["detected"])
    corrected_accepted = scan_ok and bool(vuln and patched and vuln["outcome"] == "TP" and patched["outcome"] == "TN")
    complete_success = scan_ok and corrected_accepted and all(s["outcome"] in ("TP", "TN") for s in samples)
    return legacy_accepted, corrected_accepted, complete_success


def main():
    base_ranges = load_line_ranges()
    v2_ranges = load_v2_additions()

    rows = []
    for cid in CASE_IDS:
        ep = json.loads((RUN_DIR / cid / "episode.json").read_text())
        row = {"case_id": cid}
        for cond in ("raw", "iterative"):
            ev = ep.get(cond)
            if cid == "CASE-0298":
                attempt1_rule = RUN_DIR / cid / "attempt_1" / "rule.yml"
                corrected, err = rescan_case0298(attempt1_rule)
                scan_ok = corrected["scan_ok"] if corrected else False
                samples = corrected["samples"] if corrected else []
            elif ev is None:
                scan_ok, samples = False, []
            else:
                scan_ok = ev["scan_ok"]
                samples = rescore_location(ev["samples"], v2_ranges, base_ranges, cid)
            legacy_accepted, corrected_accepted, complete_success = corrected_metrics(samples, scan_ok)
            row[cond] = {
                "scan_ok": scan_ok, "legacy_accepted": legacy_accepted,
                "corrected_accepted": corrected_accepted, "complete_success": complete_success,
                "outcomes": {s["sample_type"]: s["outcome"] for s in samples},
            }
        rows.append(row)

    out_path = ROOT / f"results/diagnostic_20261010/{RUN_NAME}_corrected_v1.json"
    if out_path.exists():
        sys.exit(f"{out_path} already exists -- refusing to overwrite.")
    out_path.write_text(json.dumps(rows, indent=2))

    print(f"Run: {RUN_NAME}")
    print(f"{'case_id':12s} {'raw:legacy':>11s} {'raw:corr':>9s} {'raw:CS':>7s}   {'it:legacy':>10s} {'it:corr':>8s} {'it:CS':>6s}")
    for r in rows:
        a, b = r["raw"], r["iterative"]
        print(f"{r['case_id']:12s} {str(a['legacy_accepted']):>11s} {str(a['corrected_accepted']):>9s} {str(a['complete_success']):>7s}   "
              f"{str(b['legacy_accepted']):>10s} {str(b['corrected_accepted']):>8s} {str(b['complete_success']):>6s}")

    for cond in ("raw", "iterative"):
        legacy_cs = sum(1 for r in rows if r[cond]["complete_success"])
        print(f"\n{cond}: complete_success under corrected evaluator = {legacy_cs}/24")

    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
